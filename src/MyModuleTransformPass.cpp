#include "MyModuleTransformPass.h"
#include "MyHBMOptions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/CommandLine.h"
#include <fstream>
#include <sstream>
#include <cmath>
#include <string>

using namespace llvm;
using namespace MyAdvancedHBM;

cl::opt<std::string> MyModuleTransformPass::HBMReportFile(
    "hbm-report-file",
    cl::desc("Path to write HBM analysis report file"),
    cl::init("")
);

cl::opt<std::string> MyModuleTransformPass::ExternalProfileFile(
    "hbm-profile-file",
    cl::desc("Optional external profile JSON file for advanced mem analysis"),
    cl::init("")
);

PreservedAnalyses MyModuleTransformPass::run(Module &M, llvm::ModuleAnalysisManager &MAM) {
  llvm::SmallVector<MallocRecord*, 16> AllMallocs;
  auto &FAMProxy = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M);
  auto &FAM = FAMProxy.getManager();
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    auto &FMI = FAM.getResult<MyFunctionAnalysisPass>(F);
    for (auto &MR : FMI.MallocRecords)
      AllMallocs.push_back(&MR);
  }
  if (!ExternalProfileFile.empty()) loadExternalProfile(M, AllMallocs);
  processMallocRecords(M, AllMallocs);
  generateReport(M, AllMallocs, true);
  return PreservedAnalyses::none();
}

void MyModuleTransformPass::loadExternalProfile(Module &M, llvm::SmallVectorImpl<MallocRecord*> &AllMallocs) {
  std::string profileFile = ExternalProfileFile.getValue();
  errs() << "[MyModuleTransformPass] Loading external profile: " << profileFile << "\n";
  std::ifstream ifs(profileFile);
  if (!ifs.is_open()) {
    errs() << "  Cannot open profile file!\n";
    return;
  }
  std::stringstream buffer;
  buffer << ifs.rdbuf();
  ifs.close();
  std::string contents = buffer.str();
  auto jsonOrErr = json::parse(contents);
  if (!jsonOrErr) {
    errs() << "  JSON parse error!\n";
    return;
  }
  auto *arr = jsonOrErr->getAsArray();
  if (!arr) {
    errs() << "  Not a JSON array!\n";
    return;
  }
  // 假设 JSON 结构为:
  // [ {"function": "foo", "line": 30, "dyn_access": 1000000, "bandwidth": 25.2, "is_stream": true}, ... ]
  for (auto &entry : *arr) {
    auto *obj = entry.getAsObject();
    if (!obj) continue;
    std::string funcName = obj->getString("function").value_or("").str();
    int lineNum = (int)obj->getNumber("line").value_or(0.0);
    double dynAccess = obj->getNumber("dyn_access").value_or(0.0);
    double bw = obj->getNumber("bandwidth").value_or(0.0);
    bool isStrm = obj->getBoolean("is_stream").value_or(false);
    for (auto *MR : AllMallocs) {
      auto *CI = MR->MallocCall;
      if (!CI) continue;
      Function *F = CI->getFunction();
      if (F->getName() != funcName)
        continue;
      auto loc = getSourceLocation(CI);
      int foundLine = 0;
      if (!loc.empty()) {
        size_t pos = loc.rfind(':');
        if (pos != std::string::npos) {
          std::string linePart = loc.substr(pos + 1);
          foundLine = atoi(linePart.c_str());
        }
      }
      if (foundLine == lineNum) {
        MR->DynamicAccessCount = (uint64_t)dynAccess;
        MR->EstimatedBandwidth = bw;
        MR->IsStreamAccess = MR->IsStreamAccess || isStrm;
        MR->Score += std::log2(dynAccess + 1) * 2.0;
        MR->Score += bw;
        if (isStrm)
          MR->Score += 10.0;
      }
    }
  }
}

void MyModuleTransformPass::processMallocRecords(Module &M, llvm::SmallVectorImpl<MallocRecord*> &AllMallocs) {
  
  // 先计算自适应阈值
  std::vector<MallocRecord> AllMallocsVec;
  for (auto *MR : AllMallocs) {
    if (MR) AllMallocsVec.push_back(*MR);
  }
  
  MyFunctionAnalysisPass MFAP;
  AdaptiveThresholdInfo ThresholdInfo = MFAP.computeAdaptiveThreshold(M, AllMallocsVec);
  
  // 输出自适应阈值信息
  errs() << "[HBM] Using adaptive threshold: " << ThresholdInfo.adjustedThreshold 
         << " (base: " << ThresholdInfo.baseThreshold 
         << "): " << ThresholdInfo.adjustmentReason << "\n";
  
  // 排序和处理 MallocRecords
  std::sort(AllMallocs.begin(), AllMallocs.end(),
            [](const MallocRecord *A, const MallocRecord *B) {
              if (A->UserForcedHot != B->UserForcedHot)
                return (A->UserForcedHot > B->UserForcedHot);
              return (A->ProfileAdjustedScore > B->ProfileAdjustedScore);
            });
  
  uint64_t used = 0ULL;
  uint64_t capacity = DefaultHBMCapacity;
  LLVMContext &Ctx = M.getContext();
  auto *Int64Ty = Type::getInt64Ty(Ctx);
  auto *Int8PtrTy = Type::getInt8PtrTy(Ctx);
  auto *VoidTy = Type::getVoidTy(Ctx);
  FunctionCallee HBMAlloc = M.getOrInsertFunction(
      "hbm_malloc",
      FunctionType::get(Int8PtrTy, {Int64Ty}, false));
  FunctionCallee HBMFree = M.getOrInsertFunction(
      "hbm_free",
      FunctionType::get(VoidTy, {Int8PtrTy}, false));
  
  for (auto *MR : AllMallocs) {
    if (!MR->MallocCall)
      continue;
    if (!MR->UserForcedHot && MR->ProfileAdjustedScore < ThresholdInfo.adjustedThreshold)
      continue;
    if (!MR->UserForcedHot && (used + MR->AllocSize > capacity))
      continue;
    
    // 提供详细的决策信息输出
    errs() << "[HBM] Moving to HBM: " << getSourceLocation(MR->MallocCall) 
    << " | Score: " << MR->ProfileAdjustedScore 
    << " | Bandwidth: " << MR->MultiDimScore.bandwidthScore
    << " | Latency: " << MR->MultiDimScore.latencyScore
    << " | Utilization: " << MR->MultiDimScore.utilizationScore
    << " | Size efficiency: " << MR->MultiDimScore.sizeEfficiencyScore
    << "\n";
    MR->MallocCall->setCalledFunction(HBMAlloc.getCallee());
    used += MR->AllocSize;
    // 直接使用 FreeCalls，而不是通过指针访问
    for (auto *fc : MR->FreeCalls)
      fc->setCalledFunction(HBMFree.getCallee());
  }
  errs() << "[MyModuleTransformPass] HBM used: " << used << "/" << capacity << "\n";
}

void MyModuleTransformPass::generateReport(const Module &M, llvm::ArrayRef<MallocRecord*> AllMallocs, bool JSONOutput) {
  if (HBMReportFile.empty()) {
    errs() << "=== HBM Analysis Report ===\n";
    json::Array root;
    for (auto *MR : AllMallocs) {
      if (!MR->MallocCall)
        continue;
      json::Object obj;
      // 位置信息
      obj["location"] = MR->SourceLocation;
      obj["size"] = MR->AllocSize;

      // 总得分
      obj["score"] = MR->Score;

      // 得分因子（加分项）
      obj["stream_score"] = MR->StreamScore;
      obj["vector_score"] = MR->VectorScore;
      obj["parallel_score"] = MR->ParallelScore;

      // 扣分因子
      obj["ssa_penalty"] = MR->SSAPenalty;
      obj["chaos_penalty"] = MR->ChaosPenalty;
      obj["conflict_penalty"] = MR->ConflictPenalty;

      // 静态分析状态
      obj["stream"] = MR->IsStreamAccess;
      obj["vectorized"] = MR->IsVectorized;
      obj["parallel"] = MR->IsParallel;
      obj["thread_partitioned"] = MR->IsThreadPartitioned;
      obj["may_conflict"] = MR->MayConflict;

      // Loop特征
      obj["loop_depth"] = MR->LoopDepth;
      obj["trip_count"] = MR->TripCount;

      // 动态 profile 信息
      obj["dyn_access"] = MR->DynamicAccessCount;
      obj["est_bw"] = MR->EstimatedBandwidth;

      // 分析矛盾标志
      obj["dynamic_hot_static_low"] = MR->WasDynamicHotButStaticLow;
      obj["static_hot_dynamic_cold"] = MR->WasStaticHotButDynamicCold;

      // 其它状态标记
      obj["forced_hot"] = MR->UserForcedHot;
      obj["unmatched_free"] = MR->UnmatchedFree;

      // 添加扩展分析结果
      // 跨函数分析
      json::Object crossFnObj;
      crossFnObj["cross_func_score"] = MR->CrossFnInfo.crossFuncScore;
      crossFnObj["called_funcs_count"] = MR->CrossFnInfo.calledFunctions.size();
      crossFnObj["caller_funcs_count"] = MR->CrossFnInfo.callerFunctions.size();
      crossFnObj["external_func_propagation"] = MR->CrossFnInfo.isPropagatedToExternalFunc;
      crossFnObj["hot_func_usage"] = MR->CrossFnInfo.isUsedInHotFunction;
      obj["cross_function"] = std::move(crossFnObj);
      
      // 数据流分析
      json::Object dataFlowObj;
      dataFlowObj["data_flow_score"] = MR->DataFlowInfo.dataFlowScore;
      dataFlowObj["has_init_phase"] = MR->DataFlowInfo.hasInitPhase;
      dataFlowObj["has_read_only_phase"] = MR->DataFlowInfo.hasReadOnlyPhase;
      dataFlowObj["has_dormant_phase"] = MR->DataFlowInfo.hasDormantPhase;
      dataFlowObj["avg_uses_per_phase"] = MR->DataFlowInfo.avgUsesPerPhase;
      obj["data_flow"] = std::move(dataFlowObj);
      
      // 竞争分析
      json::Object contentionObj;
      contentionObj["contention_score"] = MR->ContentionInfo.contentionScore;
      switch (MR->ContentionInfo.type) {
        case ContentionInfo::ContentionType::NONE:
          contentionObj["contention_type"] = "none";
          break;
        case ContentionInfo::ContentionType::FALSE_SHARING:
          contentionObj["contention_type"] = "false_sharing";
          break;
        case ContentionInfo::ContentionType::ATOMIC_CONTENTION:
          contentionObj["contention_type"] = "atomic_contention";
          break;
        case ContentionInfo::ContentionType::LOCK_CONTENTION:
          contentionObj["contention_type"] = "lock_contention";
          break;
        case ContentionInfo::ContentionType::BANDWIDTH_CONTENTION:
          contentionObj["contention_type"] = "bandwidth_contention";
          break;
      }
      contentionObj["contention_probability"] = MR->ContentionInfo.contentionProbability;
      contentionObj["contention_points"] = MR->ContentionInfo.potentialContentionPoints;
      obj["contention"] = std::move(contentionObj);

      root.push_back(std::move(obj));
    }
    std::string js;
    raw_string_ostream rso(js);
    rso << json::Value(std::move(root));
    rso.flush();
    errs() << js << "\n";
    errs() << "===========================\n";
  } else {
    std::error_code EC;
    raw_fd_ostream out(HBMReportFile.getValue(), EC, sys::fs::OF_Text);
    if (EC) {
      errs() << "Cannot open report file: " << HBMReportFile.getValue() << "\n";
      return;
    }
    json::Array root;
    for (auto *MR : AllMallocs) {
      if (!MR->MallocCall)
        continue;
      json::Object obj;
      // 位置信息
      obj["location"] = MR->SourceLocation;
      obj["size"] = MR->AllocSize;

      // 总得分
      obj["score"] = MR->Score;

      // 得分因子（加分项）
      obj["stream_score"] = MR->StreamScore;
      obj["vector_score"] = MR->VectorScore;
      obj["parallel_score"] = MR->ParallelScore;

      // 扣分因子
      obj["ssa_penalty"] = MR->SSAPenalty;
      obj["chaos_penalty"] = MR->ChaosPenalty;
      obj["conflict_penalty"] = MR->ConflictPenalty;

      // 静态分析状态
      obj["stream"] = MR->IsStreamAccess;
      obj["vectorized"] = MR->IsVectorized;
      obj["parallel"] = MR->IsParallel;
      obj["thread_partitioned"] = MR->IsThreadPartitioned;
      obj["may_conflict"] = MR->MayConflict;

      // Loop特征
      obj["loop_depth"] = MR->LoopDepth;
      obj["trip_count"] = MR->TripCount;

      // 动态 profile 信息
      obj["dyn_access"] = MR->DynamicAccessCount;
      obj["est_bw"] = MR->EstimatedBandwidth;

      // 分析矛盾标志
      obj["dynamic_hot_static_low"] = MR->WasDynamicHotButStaticLow;
      obj["static_hot_dynamic_cold"] = MR->WasStaticHotButDynamicCold;

      // 其它状态标记
      obj["forced_hot"] = MR->UserForcedHot;
      obj["unmatched_free"] = MR->UnmatchedFree;
      root.push_back(std::move(obj));
    }
    std::string js;
    raw_string_ostream rso(js);
    rso << json::Value(std::move(root));
    rso.flush();
    out << js << "\n";
  }
}

std::string MyModuleTransformPass::getSourceLocation(CallInst *CI) {
  if (!CI)
    return "";
  if (DILocation *Loc = CI->getDebugLoc()) {
    unsigned Line = Loc->getLine();
    StringRef File = Loc->getFilename();
    if (File.empty())
      return (CI->getFunction()->getName() + ":<no_file>:" + std::to_string(Line)).str();
    return (File.str() + ":" + std::to_string(Line));
  }
  auto F = CI->getFunction();
  return (F->getName() + ":<no_dbg>").str();
}
