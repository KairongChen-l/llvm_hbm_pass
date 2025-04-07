#include "MyFunctionAnalysisPass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/MemorySSA.h"
#include "llvm/Analysis/LoopAccessAnalysis.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Constants.h"
#include <queue>
#include <cmath>
#include <set>
#include <unordered_set>
#include <optional>
#include <cstdlib>

using namespace llvm;
using namespace MyAdvancedHBM;

AnalysisKey MyFunctionAnalysisPass::Key;
MyFunctionAnalysisPass::Result 
MyFunctionAnalysisPass::run(Function &F, FunctionAnalysisManager &FAM) {
  // 若函数只是声明，直接返回空结果
  if (F.isDeclaration())
    return {};

  auto &LA   = FAM.getResult<LoopAnalysis>(F);
  auto &SE   = FAM.getResult<ScalarEvolutionAnalysis>(F);
  auto &AA   = FAM.getResult<AAResults>(F);
  auto &MSSA = FAM.getResult<MemorySSAAnalysis>(F).getMSSA();
  auto &LAA  = FAM.getResult<LoopAccessAnalysis>(F);
  //判断函数内是否有并行函数调用
  bool parallelFound = detectParallelRuntime(F);
  // 所有malloc分析的vector容器
  FunctionMallocInfo FMI;
  //所有有调用free或者释放的指令
  std::vector<CallInst *> freeCalls;

  for (auto &BB : F) {
    for (auto &I : BB) {
      if (auto *CI = dyn_cast<CallInst>(&I)) {

        //检查被调用的函数
        Function *Callee = CI->getCalledFunction();
        if (!Callee) 
          continue;
        
        //获取函数名
        StringRef CalleeName = Callee->getName();

        if (CalleeName == "malloc") {
          MallocRecord MR;
          MR.MallocCall = CI;
          if (CI->arg_size() >= 1)
            MR.AllocSize = getConstantAllocSize(CI->getArgOperand(0));
            if (F.hasFnAttribute("hot_mem"))
            MR.UserForcedHot = true;
          if (CI->hasMetadata("hot_mem"))
            MR.UserForcedHot = true;
          
          //检查是否有并行函数调用
          MR.IsParallel = parallelFound;
          
          //静态分析打分
          MR.Score = analyzeMallocStatic(CI, F, LA, SE, AA, MSSA, LAA, MR);
          
          //记录到FMI中
          FMI.MallocRecords.push_back(MR);
        }
        /*
        else if (CalleeName == "memalign") {
          MallocRecord MR;
          MR.MallocCall = CI;
          if (CI->arg_size() >= 2)
            MR.AllocSize = getConstantAllocSize(CI->getArgOperand(1));
          if (F.hasFnAttribute("hot_mem"))
            MR.UserForcedHot = true;
          if (CI->hasMetadata("hot_mem"))
            MR.UserForcedHot = true;
          MR.IsParallel = parallelFound;
          MR.Score = analyzeMallocStatic(CI, F, LA, SE, AA, MSSA, LAA, MR);
          FMI.MallocRecords.push_back(MR);
        }
        */
        else if (CalleeName.startswith("_Znwm") || CalleeName.startswith("_Znam")) {
          MallocRecord MR;
          MR.MallocCall = CI;
          if (CI->arg_size() >= 1)
            MR.AllocSize = getConstantAllocSize(CI->getArgOperand(0));
          if (F.hasFnAttribute("hot_mem"))
            MR.UserForcedHot = true;
          if (CI->hasMetadata("hot_mem"))
            MR.UserForcedHot = true;
          MR.IsParallel = parallelFound;
          MR.Score = analyzeMallocStatic(CI, F, LA, SE, AA, MSSA, LAA, MR);
          FMI.MallocRecords.push_back(MR);
        }
        else if (CalleeName == "free") {
          freeCalls.push_back(CI);
        }
        else if (CalleeName.startswith("_ZdlPv") || CalleeName.startswith("_ZdaPv")) {
          freeCalls.push_back(CI);
        }
      }
    }
  }
  matchFreeCalls(FMI, freeCalls);
  return FMI;
}

double MyFunctionAnalysisPass::analyzeMallocStatic(CallInst *CI, Function &F,
    LoopAnalysis::Result &LA, ScalarEvolution &SE, AAResults &AA, MemorySSA &MSSA,
    LoopAccessAnalysis::Result &LAA, MallocRecord &MR) {
  //若传入的callinst或其分配记录有问题，返回默认值0.0
  if (!CI)
    return 0.0;

  double Score = 0.0;

  //这里可以适当调整一下分配大小的计算方式
  if (MR.AllocSize > 0) {
    double kb = static_cast<double>(MR.AllocSize) / 1024.0;
    Score += kb * 0.1;
  }
  // 递归找uses,分析内存访问和潜在流式访问
  std::unordered_set<Value *> visited;
  // 更新score以及MR中的标记是否流式访问
  explorePointerUsers(CI, CI, LA, SE, AA, MSSA, LAA, Score, MR, visited);
  // 如果是并行，则额外加分
  if (MR.IsParallel)
    Score += 20.0; // ParallelBonus
  
  //TODO 读取元数据，prof.memusage 
  if (MDNode *ProfMD = CI->getMetadata("prof.memusage")) {
    if (ProfMD->getNumOperands() > 0) {
      if (auto *Op = dyn_cast<ConstantAsMetadata>(ProfMD->getOperand(0))) {
        if (auto *CInt = dyn_cast<ConstantInt>(Op->getValue())) {
          uint64_t usage = CInt->getZExtValue();
          Score += std::sqrt((double)usage) / 10.0;
          MR.DynamicAccessCount = usage;
        }
      }
    }
  }
  //TODO 这边的分数目前是写死的状态，后期再调整吧
  if (MR.IsStreamAccess)
    Score += 10.0; // StreamBonus
  if (MR.IsVectorized)
    Score += 5.0;  // VectorBonus
  if (MR.AccessedBytes > 0 && MR.AccessTime > 0.0) {
    MR.BandwidthScore = computeBandwidthScore(MR.AccessedBytes, MR.AccessTime);
    Score += MR.BandwidthScore; // BandwidthScale假设为1.0
  }
  return Score;
}

void MyFunctionAnalysisPass::matchFreeCalls(FunctionMallocInfo &FMI, std::vector<CallInst *> &freeCalls) {
  for (auto &MR : FMI.MallocRecords) {
    Value *mallocPtr = MR.MallocCall;
    bool matched = false;
    for (auto *fc : freeCalls) {
      if (fc->arg_size() == 1) {
        Value *freeArg = fc->getArgOperand(0);
        Value *base = resolveBasePointer(freeArg);
        if (base == mallocPtr) {
          MR.FreeCalls.push_back(fc);
          matched = true;
        }
      }
    }
    if (!matched) {
      MR.UnmatchedFree = true;
      MR.Score -= 10.0;
    }
  }
}

Value* MyFunctionAnalysisPass::findBasePointer(Value *V) {
  SmallPtrSet<Value*, 16> Visited;
  SmallVector<Value*, 8> Worklist;
  Worklist.push_back(V);

  while (!Worklist.empty()) {
    Value *Cur = Worklist.pop_back_val();
    if (Visited.count(Cur)) continue;
    Visited.insert(Cur);
    if (auto *CI = dyn_cast<CallInst>(Cur)) {
      if (Function *Callee = CI->getCalledFunction()) {
        if (Callee->getName() == "malloc")
          return CI;
      }
    }
    if (auto *GEP = dyn_cast<GEPOperator>(Cur))
      Worklist.push_back(GEP->getPointerOperand());
    else if (auto *BC = dyn_cast<BitCastOperator>(Cur))
      Worklist.push_back(BC->getOperand(0));
    else if (auto *PN = dyn_cast<PHINode>(Cur))
      for (Value *Incoming : PN->incoming_values())
        Worklist.push_back(Incoming);
    else if (auto *SI = dyn_cast<SelectInst>(Cur)) {
      Worklist.push_back(SI->getTrueValue());
      Worklist.push_back(SI->getFalseValue());
    }
    else if (auto *LI = dyn_cast<LoadInst>(Cur))
      Worklist.push_back(LI->getPointerOperand());
  }
  return nullptr;
}

void MyFunctionAnalysisPass::explorePointerUsers(Value *RootPtr, Value *V,
    LoopAnalysis::Result &LA, 
    ScalarEvolution &SE, 
    AAResults &AA, 
    MemorySSA &MSSA,
    LoopAccessAnalysis::Result &LAA, 
    double &Score, MallocRecord &MR,
    std::unordered_set<Value *> &Visited) {
  
  //如果是访问过的Value，直接跳过
  if (Visited.count(V)) return;
  Visited.insert(V);

  for (User *U : V->users()) {
    if (auto *I = dyn_cast<Instruction>(U)) {
      if (auto *LD = dyn_cast<LoadInst>(I)) {
        if (LD->getType()->isVectorTy())
          MR.IsVectorized = true;
        // 计算读访问分数
        Score += computeAccessScore(LD, LA, SE, AA, MSSA, LAA, false, MR);
      }
      else if (auto *ST = dyn_cast<StoreInst>(I)) {
        if (ST->getValueOperand()->getType()->isVectorTy())
          MR.IsVectorized = true;
        Score += computeAccessScore(ST, LA, SE, AA, MSSA, LAA, true, MR);
      }
      else if (auto *CallI = dyn_cast<CallInst>(I)) {
        Function *CalledFunc = CallI->getCalledFunction();
        if (!CalledFunc)
          Score += 5.0;
        else {
          if (dyn_cast<MemIntrinsic>(CallI))
            Score += 3.0;
          else
            Score += 3.0;
        }
      }
      else if (auto *GEP = dyn_cast<GetElementPtrInst>(I)) {
        bool IsLikelyStream = true;
        for (auto idx = GEP->idx_begin(); idx != GEP->idx_end(); ++idx) {
          if (auto *CI = dyn_cast<ConstantInt>(idx->get())) {
            //如果是常量索引，判断是否为0或1，这样是很容易判断成连续的情况
            //但是跨步访问的情况也可能是stream访问，所以这里需要进一步分析
            if (CI->getSExtValue() != 0 && CI->getSExtValue() != 1) {
              IsLikelyStream = false;
              break;
            }
          } else {
              //TODO 动态索引，这边不好判断，可结合SCEV深入分析
              IsLikelyStream = false;
              break;
          }
        }
        if (IsLikelyStream)
          MR.IsStreamAccess = true;
        explorePointerUsers(RootPtr, GEP, LA, SE, AA, MSSA, LAA, Score, MR, Visited);
      }
      else if (auto *BC = dyn_cast<BitCastInst>(I))
        explorePointerUsers(RootPtr, BC, LA, SE, AA, MSSA, LAA, Score, MR, Visited);
      else if (auto *ASCI = dyn_cast<AddrSpaceCastInst>(I))
        explorePointerUsers(RootPtr, ASCI, LA, SE, AA, MSSA, LAA, Score, MR, Visited);
      else if (auto *PN = dyn_cast<PHINode>(I))
        explorePointerUsers(RootPtr, PN, LA, SE, AA, MSSA, LAA, Score, MR, Visited);
      else if (auto *SI = dyn_cast<SelectInst>(I))
        explorePointerUsers(RootPtr, SI, LA, SE, AA, MSSA, LAA, Score, MR, Visited);
      else if (dyn_cast<PtrToIntInst>(I))
        Score += 3.0;
      else if (dyn_cast<IntToPtrInst>(I))
        explorePointerUsers(RootPtr, I, LA, SE, AA, MSSA, LAA, Score, MR, Visited);
      else
        Score += 1.0;
    }
  }
}

double MyFunctionAnalysisPass::computeAccessScore(Instruction *I,
    LoopAnalysis::Result &LA, 
    ScalarEvolution &SE, 
    AAResults &AA, 
    MemorySSA &MSSA,
    LoopAccessAnalysis::Result &LAA, 
    bool isWrite, MallocRecord &MR) {
    
    // TODO : 这里的分数计算可以根据实际需求进行调整
    double base = isWrite ? 8.0 : 5.0; // AccessBaseWrite / AccessBaseRead
    BasicBlock *BB = I->getParent();
    Loop *L = LA.getLoopFor(BB);
    int depth = 0;
    uint64_t tripCount = 1;
    if (L) {
      // 计算循环深度和迭代次数
      depth = LA.getLoopDepth(BB);
      tripCount = getLoopTripCount(L, SE);

      if (tripCount == 0 || tripCount == (uint64_t)-1) tripCount = 1;
      // 此处可扩展对循环内依赖、MemorySSA等更详细判断
      // 3A) 通过 LAA 分析可能的冲突 / 依赖
      if (auto *LoopAccessInfo = LAA.getInfo(L)) {
        // 3A-1) 检查运行时指针冲突 (RuntimePointerChecking)
        if (auto *RPC = LoopAccessInfo->getRuntimePointerChecking()) {
          Value *PtrOperand = nullptr;
          if (auto *LD = dyn_cast<LoadInst>(I)) {
            PtrOperand = LD->getPointerOperand();
          } else if (auto *ST = dyn_cast<StoreInst>(I)) {
            PtrOperand = ST->getPointerOperand();
          }
          // 遍历所有需要 Runtime Check 的指针
          if (PtrOperand) {
            for (auto &PointerCheck : RPC->Pointers) {
              if (PointerCheck.PointerValue == PtrOperand) {
                // 说明这个指针在循环中存在别名不确定性，需要 runtime check
                base -= 2.0;
                break;
                // 减完一次就可以退出
              }
            }
          }
        }
        // 3A-2) 检查循环中的依赖情况
        if (const Dependences *Deps = LoopAccessInfo->getDependences()) {
          unsigned numDeps = Deps->size();
          // 这里给一个简单的扣分策略，可自行调整
          base -= (double)numDeps * 0.5;
        }
      }
      // 3B) MemorySSA 分析
      if (auto *MemAcc = MSSA.getMemoryAccess(I)) {
        if (auto *MU = dyn_cast<MemoryUse>(MemAcc)) {
          // 判断其定义者是否是 MemoryDef
          if (auto *Src = MU->getDefiningAccess()) {
            if (isa<MemoryDef>(Src)) {
              base -= 1.0;
            }
          }
        } else if (auto *MD = dyn_cast<MemoryDef>(MemAcc)) {
          base -= 0.5;
        } else if (auto *MPhi = dyn_cast<MemoryPhi>(MemAcc)) {
          base -= 0.3;
        }
      }
      // 3C) 进一步通过 SCEV 判断跨步访问
      Value *PtrOperand = nullptr;
      if (auto *LD = dyn_cast<LoadInst>(I)) {
        PtrOperand = LD->getPointerOperand();
      } else if (auto *ST = dyn_cast<StoreInst>(I)) {
        PtrOperand = ST->getPointerOperand();
      }
      if (PtrOperand && SE.isSCEVable(PtrOperand->getType())) {
        const SCEV *PtrSCEV = SE.getSCEV(PtrOperand);
        if (auto *AR = dyn_cast<SCEVAddRecExpr>(PtrSCEV)) {
          // SCEVAddRecExpr 表示 Ptr 在循环 L 中随迭代呈线性变化
          // 判断是否是线性表达式
          if (AR->isAffine()) {
            const SCEV *Step = AR->getStepRecurrence(SE);
            if (auto *StepConst = dyn_cast<SCEVConstant>(Step)) {
              int64_t Stride = StepConst->getValue()->getSExtValue();
              // 假设跨步为 1 或 -1 时属于“连续流式”
              if (std::abs(Stride) == 1) {
                MR.IsStreamAccess = true;
                base += StreamBonus;
                // 流式加分
              } else if ((Stride % 64) == 0) {
                // 对于 64 字节对齐的跨步也给一部分加成
                base += StreamBonus * 0.5;
              } else {
                // 其他跨步可视需要调节
                base -= 0.2;
                // 小幅度减分作为示例
              }
            }
          }
        }
      }
      // 3D) 使用 LoopAccessAnalysis 检查向量化潜力
      //     (仅做简易示例，可根据实际情况更加精细地判断)
      if (auto *LAI = LAA.getInfo(L)) {
        unsigned MaxSafeDepDist = LAI->getMaxSafeDepDistBytes();
        // 如果依赖距离足够大 (或者 != -1U)，就认为有较高向量化潜力
        if (MaxSafeDepDist != (unsigned)-1) {
          MR.IsVectorized = true;
          base += VectorBonus;
        }
      }
    }


    double result = base * (depth + 1) * std::sqrt((double)tripCount);
    if (MR.IsParallel)
      result += 5.0;
    //TODO 这里的分数可以根据实际的命令行输入进行调整
    if (MR.IsVectorized)
      result += 5.0;
    if (MR.IsStreamAccess)
      result += 10.0;
    return result;
}

uint64_t MyFunctionAnalysisPass::getLoopTripCount(Loop *L, ScalarEvolution &SE) {
  if (!L) return 1;
  const SCEV *BEC = SE.getBackedgeTakenCount(L);
  if (auto *SC = dyn_cast<SCEVConstant>(BEC)) {
    const APInt &val = SC->getAPInt();
    if (!val.isMaxValue())
      return val.getZExtValue() + 1;
  }
  return 1;
}

bool MyFunctionAnalysisPass::detectParallelRuntime(Function &F) {
  const std::unordered_set<std::string> ParallelEntrypoints = {
    "__kmpc_fork_call", "__kmpc_for_static_init_4", "__kmpc_for_static_init_8",
    "__kmpc_for_static_init_16", "__kmpc_for_static_init_32", "__kmpc_for_static_init_64",
    "__kmpc_push_num_threads", "__kmpc_barrier",
    "pthread_create", "pthread_join", "pthread_mutex_lock", "pthread_mutex_unlock",
    "_ZSt13__thread_call", "std::thread",
    "tbb::task_group::run", "tbb::parallel_for", "tbb::parallel_invoke",
    "clEnqueueNDRangeKernel", "cudaLaunch", "cudaMemcpyAsync"
  };

  for (auto &BB : F) {
    for (auto &I : BB) {
      if (auto *CI = dyn_cast<CallInst>(&I)) {
        Function *Callee = CI->getCalledFunction();
        // 直接调用
        if (Callee && ParallelEntrypoints.count(Callee->getName().str()))
          return true;
        // 间接调用保守判断，可以做适当拓展
          if (!Callee && CI->getCalledOperand())
          return true;
      }
    }
  }
  if (F.hasFnAttribute("omp_target_thread_limit") || F.hasFnAttribute("omp_target_parallel"))
    return true;
  return false;
}

double MyFunctionAnalysisPass::computeBandwidthScore(uint64_t approximateBytes, double approximateTime) {
  if (approximateTime <= 0.0)
    approximateTime = 1.0;
  double bwGBs = (double)approximateBytes / (1024.0 * 1024.0 * 1024.0) / approximateTime;
  return bwGBs;
}

std::optional<uint64_t> MyFunctionAnalysisPass::getConstantAllocSize(Value *V, std::set<Value*> &Visited) {
  if (!V || !Visited.insert(V).second)
    return std::nullopt;
  
  if (auto *CI = dyn_cast<ConstantInt>(V)) {
    if (CI->isNegative())
      return std::nullopt;
    
      return CI->getZExtValue();
  }
  if (auto *CE = dyn_cast<ConstantExpr>(V)) {
    auto op0 = getConstantAllocSize(CE->getOperand(0), Visited);
    auto op1 = getConstantAllocSize(CE->getOperand(1), Visited);
    if (!op0 || !op1)
      return std::nullopt;
    
      switch (CE->getOpcode()) {
      case Instruction::Add: return *op0 + *op1;
      case Instruction::Sub: return *op0 > *op1 ? std::optional(*op0 - *op1) : std::nullopt;
      case Instruction::Mul: return *op0 * *op1;
      case Instruction::UDiv: return *op1 != 0 ? std::optional(*op0 / *op1) : std::nullopt;
      case Instruction::Shl: return *op0 << *op1;
      case Instruction::And: return *op0 & *op1;
      default: break;
    }
  }
  return std::nullopt;
}

uint64_t MyFunctionAnalysisPass::getConstantAllocSize(Value *V) {
  std::set<Value*> Visited;
  auto result = getConstantAllocSize(V, Visited);
  return result.value_or(0);
}

Value* MyFunctionAnalysisPass::resolveBasePointer(Value *V) {
  std::set<Value*> visited;
  std::queue<Value*> worklist;
  worklist.push(V);
  while (!worklist.empty()) {
    Value *cur = worklist.front();
    worklist.pop();
    if (!visited.insert(cur).second)
      continue;
    if (auto *CI = dyn_cast<CallInst>(cur)) {
      if (Function *F = CI->getCalledFunction()) {
        if (F->getName().contains("malloc") || F->getName().contains("alloc"))
          return CI;
      }
    }
    if (auto *BC = dyn_cast<BitCastInst>(cur))
      worklist.push(BC->getOperand(0));
    else if (auto *GEP = dyn_cast<GetElementPtrInst>(cur))
      worklist.push(GEP->getPointerOperand());
    else if (auto *LI = dyn_cast<LoadInst>(cur))
      worklist.push(LI->getPointerOperand());
    else if (auto *PHI = dyn_cast<PHINode>(cur)) {
      for (Value *incoming : PHI->incoming_values())
        worklist.push(incoming);
    }
    else if (auto *SI = dyn_cast<SelectInst>(cur)) {
      worklist.push(SI->getTrueValue());
      worklist.push(SI->getFalseValue());
    }
  }
  return nullptr;
}
