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

bool isThreadIDRelated(llvm::Value *V) {
  using namespace llvm;
  std::queue<Value*> Q;
  std::unordered_set<Value*> Visited;
  Q.push(V);

  while (!Q.empty()) {
    Value *Cur = Q.front();
    Q.pop();
    if (!Visited.insert(Cur).second)
      continue;

    if (auto *CI = dyn_cast<CallInst>(Cur)) {
      Function *F = CI->getCalledFunction();
      if (F && (F->getName().contains("omp_get_thread_num") ||
                F->getName().contains("pthread_self") ||
                F->getName().contains("threadIdx") || 
                F->getName().contains("get_local_id"))) {
        return true;
      }
    }
    for (auto *Op : Cur->operands())
      Q.push(Op);
  }
  return false;
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
        for (auto idx = GEP->idx_begin(); idx != GEP->idx_end(); ++idx) {
          Value *IV = idx->get();
          if (isThreadIDRelated(IV)) {
            MR.IsThreadPartitioned = true;
          }
        }
        if (MR.IsParallel && !MR.IsThreadPartitioned && !MR.IsStreamAccess) {
          MR.MayConflict = true;
          Score -= 5.0; // 可根据 hbm-conflict-penalty 控制
        }        
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
double computeMemorySSAStructureScore(const llvm::Instruction *I, llvm::MemorySSA &MSSA) {
  using namespace llvm;
  const unsigned MaxDepth = 12;
  const unsigned MaxFanOut = 5;

  const MemoryAccess *Root = MSSA.getMemoryAccess(I);
  if (!Root)
    return 0.0;

  std::set<const MemoryAccess*> Visited;
  std::queue<const MemoryAccess*> Queue;
  Queue.push(Root);

  unsigned FanOutPenalty = 0;
  unsigned PhiPenalty = 0;
  unsigned NodeCount = 0;

  while (!Queue.empty() && NodeCount < 100) {
    const MemoryAccess *Cur = Queue.front();
    Queue.pop();

    if (!Visited.insert(Cur).second)
      continue;

    NodeCount++;

    // 统计 MemoryPhi 的分支数
    if (auto *MP = dyn_cast<MemoryPhi>(Cur)) {
      PhiPenalty += MP->getNumIncomingValues() - 1;
      for (auto &Op : MP->incoming_values())
        if (auto *MA = dyn_cast<MemoryAccess>(Op))
          Queue.push(MA);
    }
    // MemoryDef / MemoryUse
    else if (auto *MU = dyn_cast<MemoryUseOrDef>(Cur)) {
      const MemoryAccess *Def = MU->getDefiningAccess();
      if (Def)
        Queue.push(Def);
    }

    // Fan-out: 统计一个 MemoryAccess 被多个 MemoryUse 使用的情况
    unsigned UseCount = 0;
    for (const auto *User : Cur->users()) {
      if (isa<MemoryUseOrDef>(User))
        UseCount++;
    }
    if (UseCount > MaxFanOut)
      FanOutPenalty += UseCount - MaxFanOut;
  }

  // 聚合 penalty 转换为得分（值越高说明结构越复杂）
  double penalty = PhiPenalty * 0.5 + FanOutPenalty * 0.2;
  return std::min(penalty, 5.0); // 最多扣5分
}

double computeAccessChaosScore(llvm::Value *BasePtr, llvm::MemorySSA &MSSA, llvm::ScalarEvolution &SE) {
  using namespace llvm;

  std::unordered_set<const GetElementPtrInst*> GEPs;
  std::unordered_set<const Type*> AccessTypes;
  std::unordered_set<const Value*> IndexSources;
  unsigned BitcastCount = 0;
  unsigned IndirectIndexCount = 0;
  unsigned NonAffineAccesses = 0;

  std::queue<const Value*> Q;
  std::unordered_set<const Value*> Visited;
  Q.push(BasePtr);

  while (!Q.empty()) {
    const Value *V = Q.front();
    Q.pop();
    if (!Visited.insert(V).second)
      continue;

    for (const User *U : V->users()) {
      if (auto *I = dyn_cast<Instruction>(U)) {
        if (auto *GEP = dyn_cast<GetElementPtrInst>(I)) {
          GEPs.insert(GEP);
          for (auto idx = GEP->idx_begin(); idx != GEP->idx_end(); ++idx) {
            if (!isa<ConstantInt>(idx->get())) {
              IndexSources.insert(idx->get());
              if (isa<LoadInst>(idx->get()))
                IndirectIndexCount++;
            }
          }
          Q.push(GEP);
        } else if (auto *BC = dyn_cast<BitCastInst>(I)) {
          BitcastCount++;
          Q.push(BC);
        } else if (auto *LD = dyn_cast<LoadInst>(I)) {
          AccessTypes.insert(LD->getType());
        } else if (auto *ST = dyn_cast<StoreInst>(I)) {
          AccessTypes.insert(ST->getValueOperand()->getType());
        }
        // 检测是否是复杂的非线性 SCEV
        if (SE.isSCEVable(I->getType())) {
          const SCEV *S = SE.getSCEV(const_cast<Value*>(I));
          if (!isa<SCEVAddRecExpr>(S) && !S->isAffine()) {
            NonAffineAccesses++;
          }
        }
      }
    }
  }

  // 计算 chaos 分值
  double chaosScore = 0.0;
  if (GEPs.size() > 5)
    chaosScore += (GEPs.size() - 5) * 0.2;
  if (IndirectIndexCount > 0)
    chaosScore += IndirectIndexCount * 0.5;
  if (NonAffineAccesses > 0)
    chaosScore += NonAffineAccesses * 0.3;
  if (BitcastCount > 3)
    chaosScore += (BitcastCount - 3) * 0.2;
  if (AccessTypes.size() > 3)
    chaosScore += (AccessTypes.size() - 3) * 0.3;
  if (chaosScore > 5.0)
    chaosScore = 5.0;
  
  return chaosScore;
}

bool isLoopMarkedVectorizable(const llvm::Loop *L) {
  using namespace llvm;

  if (!L || !L->getHeader())
    return false;

  const TerminatorInst *Term = L->getHeader()->getTerminator();
  if (!Term)
    return false;

  if (MDNode *LoopMD = Term->getMetadata("llvm.loop")) {
    for (unsigned i = 0; i < LoopMD->getNumOperands(); ++i) {
      MDNode *MD = dyn_cast<MDNode>(LoopMD->getOperand(i));
      if (!MD || MD == LoopMD)
        continue;
      for (unsigned j = 0; j < MD->getNumOperands(); ++j) {
        if (auto *Str = dyn_cast<MDString>(MD->getOperand(j))) {
          if (Str->getString().equals("llvm.loop.vectorize.enable"))
            return true;
        }
      }
    }
  }
  return false;
}

bool isMarkedParallel(llvm::Loop *LoopPtr) {
  if (!LoopPtr || !LoopPtr->getHeader()) return false;
  llvm::Instruction *Term = LoopPtr->getHeader()->getTerminator();
  if (auto *MD = Term->getMetadata("llvm.loop")) {
    for (auto &Op : MD->operands()) {
      if (auto *Node = llvm::dyn_cast<llvm::MDNode>(Op)) {
        for (auto &Sub : Node->operands()) {
          if (auto *Str = llvm::dyn_cast<llvm::MDString>(Sub)) {
            if (Str->getString().contains("parallel_accesses"))
              return true;
          }
        }
      }
    }
  }
  return false;
}
double MyFunctionAnalysisPass::computeAccessScore(Instruction *I,
  LoopAnalysis::Result &LA, 
  ScalarEvolution &SE, 
  AAResults &AA, 
  MemorySSA &MSSA,
  LoopAccessAnalysis::Result &LAA, 
  bool isWrite, MallocRecord &MR) {

  using namespace MyHBMOptions;

  double base = isWrite ? AccessBaseWrite : AccessBaseRead;
  BasicBlock *BB = I->getParent();
  Loop *L = LA.getLoopFor(BB);
  int depth = 0;
  uint64_t tripCount = 1;

  if (L) {
    depth = LA.getLoopDepth(BB);
    tripCount = getLoopTripCount(L, SE);
    if (tripCount == 0 || tripCount == (uint64_t)-1) tripCount = 1;

    // 指针操作对象提取
    Value *PtrOperand = nullptr;
    if (auto *LD = dyn_cast<LoadInst>(I))
      PtrOperand = LD->getPointerOperand();
    else if (auto *ST = dyn_cast<StoreInst>(I))
      PtrOperand = ST->getPointerOperand();

    // ===== MemorySSA 结构复杂度分析 =====
    double ssaComplexity = computeMemorySSAStructureScore(I, MSSA);
    base -= ssaComplexity;
    MR.SSAComplexityScore = ssaComplexity;

    // ===== LoopAccessAnalysis 依赖冲突检测 =====
    auto *LAI = LAA.getInfo(L);
    if (LAI) {
      if (auto *RPC = LAI->getRuntimePointerChecking()) {
        for (auto &Check : RPC->Pointers) {
          if (Check.PointerValue == PtrOperand) {
            base -= 2.0;
            break;
          }
        }
      }
      if (const Dependences *Deps = LAI->getDependences()) {
        base -= (double)Deps->size() * 0.5;
      }
    }

    // ===== SCEV 基于步长的流式访问分析 =====
    if (PtrOperand && SE.isSCEVable(PtrOperand->getType())) {
      const SCEV *PtrSCEV = SE.getSCEV(PtrOperand);
      if (auto *AR = dyn_cast<SCEVAddRecExpr>(PtrSCEV)) {
        if (AR->isAffine()) {
          if (auto *StepConst = dyn_cast<SCEVConstant>(AR->getStepRecurrence(SE))) {
            int64_t Stride = StepConst->getValue()->getSExtValue();
            if (Stride != 0) {
              MR.IsStreamAccess = true;
              int64_t absStride = std::abs(Stride);
              if (absStride == 1)
                base += StreamBonus;
              else if (absStride % 64 == 0)
                base += StreamBonus * 0.8;
              else if (absStride < 1024)
                base += StreamBonus * 0.5;
              else
                base += StreamBonus * 0.2;
            }
          }
        }
      }
    }

    // ===== LoopAccessInfo 的 symbolic stride 判定 =====
    if (LAI) {
      auto &StrideMap = LAI->getSymbolicStrides();
      auto It = StrideMap.find(PtrOperand);
      if (It != StrideMap.end()) {
        MR.IsStreamAccess = true;
        base += StreamBonus * 0.6;
      }
    }

    // ===== 多维数组访问结构分析 =====
    if (auto *GEP = dyn_cast<GetElementPtrInst>(PtrOperand)) {
      const SCEV *S = SE.getSCEV(GEP);
      if (auto *AddRec = dyn_cast<SCEVAddRecExpr>(S)) {
        if (AddRec->isAffine()) {
          MR.IsStreamAccess = true;
          base += StreamBonus * 0.4;
        }
      } else if (S->isAffine()) {
        MR.IsStreamAccess = true;
        base += StreamBonus * 0.3;
      }
    }

    // ===== 向量化潜力判定 =====
    if (LAI && LAI->getMaxSafeDepDistBytes() != (unsigned)-1) {
      MR.IsVectorized = true;
      base += VectorBonus;
    }

    // ===== 向量化metadata标记判定 =====
    if (isLoopMarkedVectorizable(L)) {
      MR.IsVectorized = true;
      base += VectorBonus;
    }

    // ===== 并行化分析 =====
    if (MR.IsParallel) {
      bool IsLoopSafe = LAI && LAI->isDependencySafe();
      bool MarkedParallel = isMarkedParallel(L);
      bool ThreadPartitioned = PtrOperand && isThreadIDRelated(PtrOperand);

      if ((IsLoopSafe || MarkedParallel) && ThreadPartitioned) {
        MR.IsThreadPartitioned = true;
        base += ParallelBonus * 1.5;
      } else if (IsLoopSafe || MarkedParallel) {
        MR.MayConflict = true;
        base -= ParallelBonus * 0.5;
      } else {
        MR.MayConflict = true;
        base -= ParallelBonus;
      }
    }
  }

  // ===== 混乱度评分 =====
  double chaos = computeAccessChaosScore(PtrOperand, MSSA, SE);
  MR.ChaosScore = chaos;
  base -= chaos;

  // ===== 最终得分计算 =====
  double score = base * (depth + 1) * std::sqrt((double)tripCount);
  if (MR.IsParallel)
    score += ParallelBonus;
  if (MR.IsVectorized)
    score += VectorBonus;
  if (MR.IsStreamAccess)
    score += StreamBonus;

  // ===== 动态 profile 融合校正评分 =====
  if (MR.DynamicAccessCount > 0) {
    double dynamicWeight = std::log((double)MR.DynamicAccessCount + 1.0);

    // 若静态判定为混乱，但运行热度很高 → 加回一定权重
    if (MR.ChaosScore > 2.0 && dynamicWeight > 10.0) {
      score += dynamicWeight * 0.3; // 补偿
    }

    // 若静态分高，但动态访问极少 → 说明是伪热点
    if (score > 50.0 && dynamicWeight < 5.0) {
      score -= 10.0; // 降权
    }

    // 若 MemorySSA结构复杂，但运行时确实频繁访问，也应部分补偿
    if (MR.SSAComplexityScore > 2.0 && dynamicWeight > 10.0) {
      score += 2.0;
    }
  }

  return score;
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
