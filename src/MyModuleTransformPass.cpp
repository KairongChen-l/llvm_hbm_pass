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
  std::sort(AllMallocs.begin(), AllMallocs.end(),
            [](const MallocRecord *A, const MallocRecord *B) {
              if (A->UserForcedHot != B->UserForcedHot)
                return (A->UserForcedHot > B->UserForcedHot);
              return (A->Score > B->Score);
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
    if (!MR->UserForcedHot && MR->Score < MyHBMOptions::HBMThreshold)
      continue;
    if (!MR->UserForcedHot && (used + MR->AllocSize > capacity))
      continue;
    MR->MallocCall->setCalledFunction(HBMAlloc.getCallee());
    used += MR->AllocSize;
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
      obj["location"] = getSourceLocation(MR->MallocCall);
      obj["size"] = (double)MR->AllocSize;
      obj["score"] = MR->Score;
      obj["forced_hot"] = MR->UserForcedHot;
      obj["unmatched_free"] = MR->UnmatchedFree;
      obj["dyn_access"] = (double)MR->DynamicAccessCount;
      obj["est_bw"] = MR->EstimatedBandwidth;
      obj["stream"] = MR->IsStreamAccess;
      obj["vectorized"] = MR->IsVectorized;
      obj["parallel"] = MR->IsParallel;
      obj["thread_partitioned"] = MR->IsThreadPartitioned;
      obj["may_conflict"] = MR->MayConflict;
      obj["chaos_score"] = MR->ChaosScore;
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
      obj["location"] = getSourceLocation(MR->MallocCall);
      obj["size"] = (double)MR->AllocSize;
      obj["score"] = MR->Score;
      obj["forced_hot"] = MR->UserForcedHot;
      obj["unmatched_free"] = MR->UnmatchedFree;
      obj["dyn_access"] = (double)MR->DynamicAccessCount;
      obj["est_bw"] = MR->EstimatedBandwidth;
      obj["stream"] = MR->IsStreamAccess;
      obj["vectorized"] = MR->IsVectorized;
      obj["parallel"] = MR->IsParallel;
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
