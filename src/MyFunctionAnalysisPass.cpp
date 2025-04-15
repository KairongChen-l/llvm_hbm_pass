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
MyFunctionAnalysisPass::run(Function &F, FunctionAnalysisManager &FAM)
{
  // 若函数只是声明，直接返回空结果
  if (F.isDeclaration())
    return {};

  auto &LA = FAM.getResult<LoopAnalysis>(F);
  auto &SE = FAM.getResult<ScalarEvolutionAnalysis>(F);
  auto &AA = FAM.getResult<AAResults>(F);
  auto &MSSA = FAM.getResult<MemorySSAAnalysis>(F).getMSSA();
  auto &LAA = FAM.getResult<LoopAccessAnalysis>(F);
  // 判断函数内是否有并行函数调用
  bool parallelFound = detectParallelRuntime(F);
  // 所有malloc分析的vector容器
  FunctionMallocInfo FMI;
  // 所有有调用free或者释放的指令
  std::vector<CallInst *> freeCalls;

  for (auto &BB : F)
  {
    for (auto &I : BB)
    {
      if (auto *CI = dyn_cast<CallInst>(&I))
      {

        // 检查被调用的函数
        Function *Callee = CI->getCalledFunction();
        if (!Callee)
          continue;

        // 获取函数名
        StringRef CalleeName = Callee->getName();

        if (CalleeName == "malloc")
        {
          MallocRecord MR;
          MR.MallocCall = CI;
          if (CI->arg_size() >= 1)
            MR.AllocSize = getConstantAllocSize(CI->getArgOperand(0));
          if (F.hasFnAttribute("hot_mem"))
            MR.UserForcedHot = true;
          if (CI->hasMetadata("hot_mem"))
            MR.UserForcedHot = true;

          // 检查是否有并行函数调用
          MR.IsParallel = parallelFound;

          // 静态分析打分
          MR.Score = analyzeMallocStatic(CI, F, LA, SE, AA, MSSA, LAA, MR);

          // 记录到FMI中
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
        else if (CalleeName.startswith("_Znwm") || CalleeName.startswith("_Znam"))
        {
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
        else if (CalleeName == "free")
        {
          freeCalls.push_back(CI);
        }
        else if (CalleeName.startswith("_ZdlPv") || CalleeName.startswith("_ZdaPv"))
        {
          freeCalls.push_back(CI);
        }
      }
    }
  }
  matchFreeCalls(FMI, freeCalls);
  return FMI;
}

double MyFunctionAnalysisPass::analyzeMallocStatic(CallInst *CI,
                                                   Function &F,
                                                   LoopAnalysis::Result &LA,
                                                   ScalarEvolution &SE,
                                                   AAResults &AA,
                                                   MemorySSA &MSSA,
                                                   LoopAccessAnalysis::Result &LAA,
                                                   MallocRecord &MR)
{
  // 若传入的callinst或其分配记录有问题，返回默认值0.0
  if (!CI)
    return 0.0;

  double Score = 0.0;

  // 获取模块信息
  Module *M = F.getParent();

  // 添加跨函数分析
  MR.CrossFnInfo = analyzeCrossFunctionUsage(CI, *M);
  Score += MR.CrossFnInfo.crossFuncScore;

  // 添加数据流分析
  MR.DataFlowInfo = analyzeDataFlow(CI, F);
  Score += MR.DataFlowInfo.dataFlowScore;

  // 添加竞争分析
  MR.ContentionInfo = analyzeContention(CI, F);
  Score += MR.ContentionInfo.contentionScore;

  // 添加Profile引导分析
  MR.ProfileInfo = analyzeProfileData(CI, F);
  // 添加多维度评分计算
  MR.MultiDimScore = computeMultiDimensionalScore(MR);
  // 使用Profile数据调整分数
  MR.ProfileAdjustedScore = adjustScoreWithProfile(Score, MR.ProfileInfo);

  // 这里可以适当调整一下分配大小的计算方式
  if (MR.AllocSize > 0)
  {
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

  // TODO 读取元数据，prof.memusage
  if (MDNode *ProfMD = CI->getMetadata("prof.memusage"))
  {
    if (ProfMD->getNumOperands() > 0)
    {
      if (auto *Op = dyn_cast<ConstantAsMetadata>(ProfMD->getOperand(0)))
      {
        if (auto *CInt = dyn_cast<ConstantInt>(Op->getValue()))
        {
          uint64_t usage = CInt->getZExtValue();
          Score += std::sqrt((double)usage) / 10.0;
          MR.DynamicAccessCount = usage;
        }
      }
    }
  }
  // TODO 这边的分数目前是写死的状态，后期再调整吧
  if (MR.IsStreamAccess)
    Score += 10.0; // StreamBonus
  if (MR.IsVectorized)
    Score += 5.0; // VectorBonus
  if (MR.AccessedBytes > 0 && MR.AccessTime > 0.0)
  {
    MR.BandwidthScore = computeBandwidthScore(MR.AccessedBytes, MR.AccessTime);
    Score += MR.BandwidthScore; // BandwidthScale假设为1.0
  }
  // 返回调整后的分数
  return Score;
}

// ok  需要再确认一遍
bool MyFunctionAnalysisPass::isStreamingAccess(Value *Ptr, ScalarEvolution &SE, AAResults &AA, Loop *L)
{
  if (!Ptr || !SE.isSCEVable(Ptr->getType()))
    return false;

  // 获取指针的SCEV表达式
  const SCEV *PtrSCEV = SE.getSCEV(Ptr);

  // 分析是否为仿射加递归表达式（线性变化）
  if (auto *AR = dyn_cast<SCEVAddRecExpr>(PtrSCEV))
  {
    if (AR->isAffine())
    {
      // 获取步长
      const SCEV *Step = AR->getStepRecurrence(SE);

      // 检查步长是否为常量
      if (auto *ConstStep = dyn_cast<SCEVConstant>(Step))
      {
        // 获取步长值
        int64_t StrideVal = ConstStep->getValue()->getSExtValue();

        // stride-1 是最理想的连续访问模式
        if (StrideVal == 1)
          return true;

        // 检查步长是否与类型大小匹配（可能是按元素访问）
        if (auto *PtrTy = dyn_cast<PointerType>(Ptr->getType()))
        {
          if (auto *ElemTy = PtrTy->getElementType())
          {
            const DataLayout &DL = Ptr->getModule()->getDataLayout();
            uint64_t ElemSize = DL.getTypeAllocSize(ElemTy);

            // 步长等于元素大小，是按元素顺序访问
            if (StrideVal == (int64_t)ElemSize)
              return true;

            // 步长是元素大小的倍数，可能是跳跃访问但仍保持规则性
            if (StrideVal % (int64_t)ElemSize == 0 && StrideVal < 1024)
              return true;
          }
        }

        // 其他固定步长，如果不是太大，也可以算作流式
        if (std::abs(StrideVal) <= 1024)
          return true;
      }
    }
  }

  // 对于不直接表现为加递归的指针，检查是否通过GEP访问
  if (auto *GEP = dyn_cast<GetElementPtrInst>(Ptr))
  {
    bool AllConstantOrLinear = true;

    // 检查GEP的索引是否都是常量或线性变化
    for (auto I = GEP->idx_begin(), E = GEP->idx_end(); I != E; ++I)
    {
      Value *Idx = *I;

      // 常量索引是OK的
      if (isa<ConstantInt>(Idx))
        continue;

      // 检查非常量索引是否为线性变化
      if (!SE.isSCEVable(Idx->getType()) ||
          !isa<SCEVAddRecExpr>(SE.getSCEV(Idx)) ||
          !cast<SCEVAddRecExpr>(SE.getSCEV(Idx))->isAffine())
      {
        AllConstantOrLinear = false;
        break;
      }
    }

    if (AllConstantOrLinear)
      return true;
  }

  // 如果循环被标记为可向量化，这通常意味着访问是规则的
  if (L && isLoopMarkedVectorizable(L))
    return true;

  // 使用LoopAccessAnalysis来检查是否安全向量化，这通常意味着访问是规则的
  if (L)
  {
    auto *LAI = LAA.getInfo(L);
    if (LAI && LAI->getMaxSafeDepDistBytes() != (unsigned)-1)
      return true;
  }

  // 检查是否进行了数组范围内的线性访问（通过依赖分析）
  if (L && Ptr)
  {
    // 获取指针所指向的可能对象集合
    AliasResult AR = AA.alias(MemoryLocation(Ptr), MemoryLocation::getBeforeOrAfter());

    // 如果我们确定它只指向一个对象，这可能是单个数组范围内的访问
    if (AR == AliasResult::MustAlias)
    {
      return true;
    }
  }

  return false;
}

// ok
StrideType MyFunctionAnalysisPass::analyzeGEPStride(GetElementPtrInst *GEP, ScalarEvolution &SE)
{
  if (!GEP)
    return StrideType::UNKNOWN;

  StrideType Result = StrideType::CONSTANT; // 默认假设是常量步长

  // 基地址必须是固定的
  Value *BasePtr = GEP->getPointerOperand();
  if (!isa<Argument>(BasePtr) && !isa<AllocaInst>(BasePtr) && !isa<GlobalValue>(BasePtr) &&
      !isa<CallInst>(BasePtr))
  {
    return StrideType::UNKNOWN; // 基地址不固定，无法确定步长
  }

  bool HasVariableIndex = false;
  for (auto Idx = GEP->idx_begin(), E = GEP->idx_end(); Idx != E; ++Idx)
  {
    Value *IdxVal = *Idx;

    // 跳过常量索引
    if (isa<ConstantInt>(IdxVal))
      continue;

    HasVariableIndex = true;

    if (SE.isSCEVable(IdxVal->getType()))
    {
      const SCEV *IdxSCEV = SE.getSCEV(IdxVal);

      // 检查是否为线性变化
      if (auto *AR = dyn_cast<SCEVAddRecExpr>(IdxSCEV))
      {
        if (AR->isAffine())
        {
          Result = std::max(Result, StrideType::LINEAR);
          continue;
        }
      }

      // 不是线性的，但可能是复杂的但规则的模式
      if (SE.hasComputableLoopEvolution(IdxSCEV, nullptr))
      {
        Result = std::max(Result, StrideType::COMPLEX);
        continue;
      }
    }

    // 无法通过SCEV确定规律，检查是否是简单算术
    if (Instruction *IdxInst = dyn_cast<Instruction>(IdxVal))
    {
      if (IdxInst->getOpcode() == Instruction::Add ||
          IdxInst->getOpcode() == Instruction::Sub ||
          IdxInst->getOpcode() == Instruction::Mul)
      {
        Result = std::max(Result, StrideType::COMPLEX);
        continue;
      }
    }

    // 如果能走到这里，说明索引无法确定规则性
    return StrideType::IRREGULAR;
  }

  // 如果没有变量索引，就是纯常量偏移
  if (!HasVariableIndex)
    return StrideType::CONSTANT;

  return Result;
}

// ok
void MyFunctionAnalysisPass::matchFreeCalls(FunctionMallocInfo &FMI, std::vector<CallInst *> &freeCalls)
{
  for (auto &MR : FMI.MallocRecords)
  {
    Value *mallocPtr = MR.MallocCall;
    bool matched = false;
    for (auto *fc : freeCalls)
    {
      if (fc->arg_size() == 1)
      {
        Value *freeArg = fc->getArgOperand(0);
        Value *base = resolveBasePointer(freeArg);
        if (base == mallocPtr)
        {
          // 直接使用 FreeCalls 成员，而不是通过指针访问
          MR.FreeCalls.push_back(fc);
          matched = true;
        }
      }
    }
    if (!matched)
    {
      MR.UnmatchedFree = true;
      MR.Score -= 10.0;
    }
  }
}

// ok 但是在检查线程id的部分代码好像不一样
bool isThreadIDRelated(llvm::Value *V)
{
  using namespace llvm;
  std::queue<Value *> Q;
  std::unordered_set<Value *> Visited;
  Q.push(V);

  while (!Q.empty())
  {
    Value *Cur = Q.front();
    Q.pop();
    if (!Visited.insert(Cur).second)
      continue;

    if (auto *CI = dyn_cast<CallInst>(Cur))
    {
      Function *F = CI->getCalledFunction();
      if (F && (F->getName().contains("omp_get_thread_num") ||
                F->getName().contains("pthread_self") ||
                F->getName().contains("threadIdx") ||
                F->getName().contains("get_local_id")))
      {
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
                                                 std::unordered_set<Value *> &Visited)
{

  // 如果是访问过的Value，直接跳过
  if (Visited.count(V))
    return;
  Visited.insert(V);

  for (User *U : V->users())
  {
    if (auto *I = dyn_cast<Instruction>(U))
    {
      if (auto *LD = dyn_cast<LoadInst>(I))
      {
        if (LD->getType()->isVectorTy())
          MR.IsVectorized = true;
        // 计算读访问分数
        Score += computeAccessScore(LD, LA, SE, AA, MSSA, LAA, false, MR);
      }
      else if (auto *ST = dyn_cast<StoreInst>(I))
      {
        if (ST->getValueOperand()->getType()->isVectorTy())
          MR.IsVectorized = true;
        Score += computeAccessScore(ST, LA, SE, AA, MSSA, LAA, true, MR);
      }
      else if (auto *CallI = dyn_cast<CallInst>(I))
      {
        Function *CalledFunc = CallI->getCalledFunction();
        if (!CalledFunc)
          Score += 5.0;
        else
        {
          if (dyn_cast<MemIntrinsic>(CallI))
            Score += 3.0;
          else
            Score += 3.0;
        }
      }
      else if (auto *GEP = dyn_cast<GetElementPtrInst>(I))
      {
        for (auto idx = GEP->idx_begin(); idx != GEP->idx_end(); ++idx)
        {
          Value *IV = idx->get();
          if (isThreadIDRelated(IV))
          {
            MR.IsThreadPartitioned = true;
          }
        }
        if (MR.IsParallel && !MR.IsThreadPartitioned && !MR.IsStreamAccess)
        {
          MR.MayConflict = true;
          Score -= 5.0; // 可根据 hbm-conflict-penalty 控制
        }
        bool IsLikelyStream = true;
        for (auto idx = GEP->idx_begin(); idx != GEP->idx_end(); ++idx)
        {
          if (auto *CI = dyn_cast<ConstantInt>(idx->get()))
          {
            // 如果是常量索引，判断是否为0或1，这样是很容易判断成连续的情况
            // 但是跨步访问的情况也可能是stream访问，所以这里需要进一步分析
            if (CI->getSExtValue() != 0 && CI->getSExtValue() != 1)
            {
              IsLikelyStream = false;
              break;
            }
          }
          else
          {
            // TODO 动态索引，这边不好判断，可结合SCEV深入分析
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
double MyFunctionAnalysisPass::computeMemorySSAStructureScore(const llvm::Instruction *I, llvm::MemorySSA &MSSA)
{
  using namespace llvm;
  const unsigned MaxDepth = 12;
  const unsigned MaxFanOut = 5;

  const MemoryAccess *Root = MSSA.getMemoryAccess(I);
  if (!Root)
    return 0.0;

  std::set<const MemoryAccess *> Visited;
  std::queue<const MemoryAccess *> Queue;
  Queue.push(Root);

  unsigned FanOutPenalty = 0;
  unsigned PhiPenalty = 0;
  unsigned NodeCount = 0;

  while (!Queue.empty() && NodeCount < 100)
  {
    const MemoryAccess *Cur = Queue.front();
    Queue.pop();

    if (!Visited.insert(Cur).second)
      continue;

    NodeCount++;

    // 统计 MemoryPhi 的分支数
    if (auto *MP = dyn_cast<MemoryPhi>(Cur))
    {
      PhiPenalty += MP->getNumIncomingValues() - 1;
      for (auto &Op : MP->incoming_values())
        if (auto *MA = dyn_cast<MemoryAccess>(Op))
          Queue.push(MA);
    }
    // MemoryDef / MemoryUse
    else if (auto *MU = dyn_cast<MemoryUseOrDef>(Cur))
    {
      const MemoryAccess *Def = MU->getDefiningAccess();
      if (Def)
        Queue.push(Def);
    }

    // Fan-out: 统计一个 MemoryAccess 被多个 MemoryUse 使用的情况
    unsigned UseCount = 0;
    for (const auto *User : Cur->users())
    {
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

double computeAccessChaosScore(llvm::Value *BasePtr, llvm::MemorySSA &MSSA, llvm::ScalarEvolution &SE)
{
  using namespace llvm;

  std::unordered_set<const GetElementPtrInst *> GEPs;
  std::unordered_set<const Type *> AccessTypes;
  std::unordered_set<const Value *> IndexSources;
  unsigned BitcastCount = 0;
  unsigned IndirectIndexCount = 0;
  unsigned NonAffineAccesses = 0;

  std::queue<const Value *> Q;
  std::unordered_set<const Value *> Visited;
  Q.push(BasePtr);

  while (!Q.empty())
  {
    const Value *V = Q.front();
    Q.pop();
    if (!Visited.insert(V).second)
      continue;

    for (const User *U : V->users())
    {
      if (auto *I = dyn_cast<Instruction>(U))
      {
        if (auto *GEP = dyn_cast<GetElementPtrInst>(I))
        {
          GEPs.insert(GEP);
          for (auto idx = GEP->idx_begin(); idx != GEP->idx_end(); ++idx)
          {
            if (!isa<ConstantInt>(idx->get()))
            {
              IndexSources.insert(idx->get());
              if (isa<LoadInst>(idx->get()))
                IndirectIndexCount++;
            }
          }
          Q.push(GEP);
        }
        else if (auto *BC = dyn_cast<BitCastInst>(I))
        {
          BitcastCount++;
          Q.push(BC);
        }
        else if (auto *LD = dyn_cast<LoadInst>(I))
        {
          AccessTypes.insert(LD->getType());
        }
        else if (auto *ST = dyn_cast<StoreInst>(I))
        {
          AccessTypes.insert(ST->getValueOperand()->getType());
        }
        // 检测是否是复杂的非线性 SCEV
        if (SE.isSCEVable(I->getType()))
        {
          const SCEV *S = SE.getSCEV(const_cast<Value *>(I));
          if (!isa<SCEVAddRecExpr>(S) && !S->isAffine())
          {
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

bool isLoopMarkedVectorizable(const llvm::Loop *L)
{
  using namespace llvm;

  if (!L || !L->getHeader())
    return false;

  const TerminatorInst *Term = L->getHeader()->getTerminator();
  if (!Term)
    return false;

  if (MDNode *LoopMD = Term->getMetadata("llvm.loop"))
  {
    for (unsigned i = 0; i < LoopMD->getNumOperands(); ++i)
    {
      MDNode *MD = dyn_cast<MDNode>(LoopMD->getOperand(i));
      if (!MD || MD == LoopMD)
        continue;
      for (unsigned j = 0; j < MD->getNumOperands(); ++j)
      {
        if (auto *Str = dyn_cast<MDString>(MD->getOperand(j)))
        {
          if (Str->getString().equals("llvm.loop.vectorize.enable"))
            return true;
        }
      }
    }
  }
  return false;
}

bool isMarkedParallel(llvm::Loop *LoopPtr)
{
  if (!LoopPtr || !LoopPtr->getHeader())
    return false;
  llvm::Instruction *Term = LoopPtr->getHeader()->getTerminator();
  if (auto *MD = Term->getMetadata("llvm.loop"))
  {
    for (auto &Op : MD->operands())
    {
      if (auto *Node = llvm::dyn_cast<llvm::MDNode>(Op))
      {
        for (auto &Sub : Node->operands())
        {
          if (auto *Str = llvm::dyn_cast<llvm::MDString>(Sub))
          {
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
                                                  bool isWrite,
                                                  MallocRecord &MR)
{

  using namespace MyHBMOptions;

  double base = isWrite ? AccessBaseWrite : AccessBaseRead;
  BasicBlock *BB = I->getParent();
  Loop *L = LA.getLoopFor(BB);
  int depth = 0;
  uint64_t tripCount = 1;

  // 访问的指针操作对象
  // 这里的PtrOperand是指LoadInst/StoreInst的操作数
  Value *PtrOperand = nullptr;
  if (auto *LD = dyn_cast<LoadInst>(I))
    PtrOperand = LD->getPointerOperand();
  else if (auto *ST = dyn_cast<StoreInst>(I))
    PtrOperand = ST->getPointerOperand();

  if (L)
  {
    depth = LA.getLoopDepth(BB);
    tripCount = getLoopTripCount(L, SE);
    if (tripCount == 0 || tripCount == (uint64_t)-1)
      tripCount = 1;
    MR.LoopDepth = depth;
    MR.TripCount = tripCount;

    // ===== 新增：嵌套循环分析 =====
    if (PtrOperand)
    {
      double nestedLoopScore = analyzeNestedLoops(L, PtrOperand, SE, LA);
      MR.StreamScore += nestedLoopScore * 0.3;
      base += nestedLoopScore * 0.3;
    }

    // ===== 新增：数据局部性分析 =====
    if (PtrOperand)
    {
      LocalityType locality = analyzeDataLocality(PtrOperand, L, SE);
      switch (locality)
      {
      case LocalityType::EXCELLENT:
        // 极佳的局部性可能不太需要HBM
        base += StreamBonus * 0.2;
        break;
      case LocalityType::GOOD:
        // 良好的局部性，但仍可从HBM受益
        base += StreamBonus * 0.5;
        break;
      case LocalityType::MODERATE:
        // 中等局部性，更可能从HBM受益
        base += StreamBonus * 0.8;
        break;
      case LocalityType::POOR:
        // 差的局部性，非常需要HBM
        base += StreamBonus * 1.2;
        MR.IsStreamAccess = true; // 标记为流式访问
        break;
      }
    }

    // ===== 新增：交错访问模式分析 =====
    InterleavedAccessInfo interleavedInfo = analyzeInterleavedAccess(L, SE);
    if (interleavedInfo.isInterleaved)
    {
      if (interleavedInfo.isPotentiallyBandwidthBound)
      {
        // 交错访问多个数组，可能是带宽密集型
        MR.IsStreamAccess = true;
        double interleaveBonus = StreamBonus * 0.7 * (0.5 + 0.1 * interleavedInfo.accessedArrays);
        MR.StreamScore += interleaveBonus;
        base += interleaveBonus;
      }
    }

    // ===== 增强的并行访问分析 =====
    if (MR.IsParallel && PtrOperand)
    {
      // 分析线程访问模式
      ThreadAccessPattern AccessPattern = analyzeThreadAccess(PtrOperand, I);

      switch (AccessPattern)
      {
      case ThreadAccessPattern::PARTITIONED:
        // 按线程ID分区访问（良性）
        MR.IsThreadPartitioned = true;
        MR.MayConflict = false;

        // 估计并行线程数并根据线程数增加权重
        unsigned NumThreads = estimateParallelThreads(*I->getFunction());
        double threadFactor = std::min(8.0, std::log2(double(NumThreads)));
        double parallelBonus = ParallelBonus * (1.0 + 0.2 * threadFactor);

        MR.ParallelScore += parallelBonus;
        base += parallelBonus;
        break;

      case ThreadAccessPattern::SHARED_READONLY:
        // 只读共享（良性，但带宽需求取决于线程数）
        MR.IsThreadPartitioned = false;
        MR.MayConflict = false;

        // 只读共享在并行环境中也会增加带宽需求
        MR.ParallelScore += ParallelBonus * 0.7;
        base += ParallelBonus * 0.7;
        break;

      case ThreadAccessPattern::ATOMIC_ACCESS:
        // 原子访问（有同步开销，但不一定是带宽瓶颈）
        MR.IsThreadPartitioned = false;
        MR.MayConflict = true;

        // 原子操作通常不是带宽密集型的
        MR.ParallelScore += ParallelBonus * 0.3;
        base += ParallelBonus * 0.3;
        break;

      case ThreadAccessPattern::FALSE_SHARING:
        // 伪共享（不良）
        MR.IsThreadPartitioned = false;
        MR.MayConflict = true;

        // 伪共享会导致性能问题，但通常不是带宽瓶颈
        MR.ConflictPenalty += ParallelBonus * 0.8;
        base -= ParallelBonus * 0.8;
        break;

      case ThreadAccessPattern::SHARED_WRITE:
        // 写入共享（可能有冲突）
        MR.IsThreadPartitioned = false;
        MR.MayConflict = true;

        // 共享写入可能导致缓存一致性流量
        MR.ConflictPenalty += ParallelBonus * 0.5;
        base -= ParallelBonus * 0.5;
        break;

      case ThreadAccessPattern::PRIVATE:
        // 线程私有数据
        MR.IsThreadPartitioned = true;
        MR.MayConflict = false;

        // 私有数据在并行环境中通常不是带宽瓶颈
        MR.ParallelScore += ParallelBonus * 0.5;
        base += ParallelBonus * 0.5;
        break;

      default:
        // 未知模式，保守处理
        MR.MayConflict = true;
        break;
      }

      // 检查是否有并行循环元数据
      if (hasParallelLoopMetadata(L))
      {
        // 编译器明确标记的并行循环通常是良性的
        MR.ParallelScore += ParallelBonus * 0.5;
        base += ParallelBonus * 0.5;
      }

      // 分析并行框架类型
      if (isOpenMPParallel(*I->getFunction()))
      {
        // OpenMP通常有良好的数据局部性
        MR.ParallelScore += ParallelBonus * 0.3;
        base += ParallelBonus * 0.3;
      }
      else if (isCUDAParallel(*I->getFunction()))
      {
        // CUDA通常有大量并行线程
        MR.ParallelScore += ParallelBonus * 0.6;
        base += ParallelBonus * 0.6;
      }
      else if (isTBBParallel(*I->getFunction()))
      {
        // TBB通常有任务窃取调度
        MR.ParallelScore += ParallelBonus * 0.4;
        base += ParallelBonus * 0.4;
      }
    }

    // ===== 增强的向量化识别 =====

    // 1. 直接检查指令是否使用向量类型或SIMD指令
    if (isVectorizedInstruction(I))
    {
      MR.IsVectorized = true;
      // 获取向量宽度并根据大小给予额外奖励
      int VecWidth = 0;
      if (auto *LD = dyn_cast<LoadInst>(I))
        VecWidth = getVectorWidth(LD->getType());
      else if (auto *ST = dyn_cast<StoreInst>(I))
        VecWidth = getVectorWidth(ST->getValueOperand()->getType());

      double vectorBonus = VectorBonus;
      if (VecWidth >= 8)
        vectorBonus *= 1.5; // 512位向量（AVX-512）
      else if (VecWidth >= 4)
        vectorBonus *= 1.2; // 256位向量（AVX）

      MR.VectorScore += vectorBonus;
      base += vectorBonus;
    }

    // 2. 检查循环是否显示出向量化模式
    if (isVectorLoopPattern(L, SE))
    {
      MR.IsVectorized = true;
      MR.VectorScore += VectorBonus * 1.2;
      base += VectorBonus * 1.2;
    }

    // 3. 检查指针操作数是否参与向量操作
    if (PtrOperand)
    {
      std::set<Value *> Visited;
      if (hasVectorOperations(PtrOperand, Visited))
      {
        MR.IsVectorized = true;
        MR.VectorScore += VectorBonus;
        base += VectorBonus;
      }
    }

    // 4. 检查函数是否包含SIMD内部函数
    Function *F = I->getFunction();
    if (F && detectSIMDIntrinsics(*F))
    {
      MR.IsVectorized = true;
      MR.VectorScore += VectorBonus * 0.8;
      base += VectorBonus * 0.8;
    }

    // 5. 分析是否有明确的向量化元数据提示
    if (MDNode *VectorizeNode = I->getMetadata("llvm.mem.parallel_loop_access") ||
                                I->getMetadata("llvm.loop.vectorize.enable"))
    {
      MR.IsVectorized = true;
      MR.VectorScore += VectorBonus * 1.3;
      base += VectorBonus * 1.3;
    }

    // 6. LoopAccessAnalysis深入分析（原有代码增强）
    if (LAA.getInfo(L))
    {
      auto *LAI = LAA.getInfo(L);

      // 检查最大安全依赖距离是否支持向量化
      if (LAI && LAI->getMaxSafeDepDistBytes() != (unsigned)-1)
      {
        MR.IsVectorized = true;

        // 额外奖励大的安全依赖距离
        unsigned MaxSafeDepDist = LAI->getMaxSafeDepDistBytes();
        double distanceFactor = std::min(1.0, double(MaxSafeDepDist) / 256.0);
        MR.VectorScore += VectorBonus * (1.0 + distanceFactor);
        base += VectorBonus * (1.0 + distanceFactor);
      }

      // 检查是否没有存储依赖阻碍向量化
      if (LAI && LAI->getDependences() && LAI->getDependences()->empty())
      {
        MR.IsVectorized = true;
        MR.VectorScore += VectorBonus * 0.5;
        base += VectorBonus * 0.5;
      }
    }

    // ===== MemorySSA 结构复杂度分析 =====
    MR.SSAPenalty = computeMemorySSAStructureScore(I, MSSA);
    base -= MR.SSAPenalty;
    // ===== 增强的流式访问分析 =====
    if (PtrOperand)
    {
      // 使用新的流式访问分析方法
      if (isStreamingAccess(PtrOperand, SE, AA, L))
      {
        MR.IsStreamAccess = true;

        // 进一步分析访问模式的精确类型
        double streamBonus = StreamBonus; // 基础流式访问奖励

        // 如果是GEP，进一步分析步长类型
        if (auto *GEP = dyn_cast<GetElementPtrInst>(PtrOperand))
        {
          StrideType stride = analyzeGEPStride(GEP, SE);

          switch (stride)
          {
          case StrideType::CONSTANT:
            streamBonus *= 1.2; // 常量步长，最优
            break;
          case StrideType::LINEAR:
            streamBonus *= 1.0; // 线性步长，很好
            break;
          case StrideType::COMPLEX:
            streamBonus *= 0.8; // 复杂但有规律，还可以
            break;
          case StrideType::IRREGULAR:
            streamBonus *= 0.5; // 不规则，但仍有一定流式特性
            break;
          default:
            streamBonus *= 0.3; // 未知
            break;
          }
        }

        // 检查是否在最内层循环，这通常是最热的访问点
        if (L->getSubLoops().empty())
        {
          streamBonus *= 1.5; // 最内层循环的流式访问更重要
        }

        MR.StreamScore += streamBonus;
        base += streamBonus;
      }
    }

    // ===== LoopAccessAnalysis 依赖冲突检测 =====
    auto *LAI = LAA.getInfo(L);
    if (LAI)
    {
      if (auto *RPC = LAI->getRuntimePointerChecking())
      {
        for (auto &Check : RPC->Pointers)
        {
          if (Check.PointerValue == PtrOperand)
          {
            MR.ConflictPenalty += 2.0;
            base -= 2.0;
            break;
          }
        }
      }
      if (const Dependences *Deps = LAI->getDependences())
      {
        double depPenalty = (double)Deps->size() * 0.5;
        MR.ConflictPenalty += depPenalty;
        base -= depPenalty;
      }
    }

    // 使用SCEV进行更精细的步长分析
    if (PtrOperand && SE.isSCEVable(PtrOperand->getType()))
    {
      const SCEV *PtrSCEV = SE.getSCEV(PtrOperand);

      if (auto *AR = dyn_cast<SCEVAddRecExpr>(PtrSCEV))
      {
        if (AR->isAffine())
        {
          // 基地址是否可能是从内存加载的？
          const SCEV *Start = AR->getStart();
          bool StartIsLoaded = false;

          // 递归检查起始值是否可能来自内存
          if (isa<SCEVUnknown>(Start))
          {
            Value *StartVal = cast<SCEVUnknown>(Start)->getValue();
            if (isa<LoadInst>(StartVal) || isMayLoadFromMemory(StartVal))
            {
              StartIsLoaded = true;
            }
          }

          if (auto *StepConst = dyn_cast<SCEVConstant>(AR->getStepRecurrence(SE)))
          {
            int64_t Stride = StepConst->getValue()->getSExtValue();

            // 特别奖励 stride-1 访问
            if (Stride == 1 && !StartIsLoaded)
            {
              MR.IsStreamAccess = true;
              MR.StreamScore += StreamBonus * 1.5;
              base += StreamBonus * 1.5;
            }
            // 正步长，按递增访问（良好的访问模式）
            else if (Stride > 0 && !StartIsLoaded)
            {
              MR.IsStreamAccess = true;

              // 小步长更好
              double strideFactor = std::min(1.0, 32.0 / double(Stride));
              MR.StreamScore += StreamBonus * strideFactor;
              base += StreamBonus * strideFactor;
            }
            // 负步长，逆序访问（通常依然是良好模式，但可能略差）
            else if (Stride < 0)
            {
              MR.IsStreamAccess = true;
              MR.StreamScore += StreamBonus * 0.8;
              base += StreamBonus * 0.8;
            }
            // 0 步长，不变地址，重复访问一个位置（不是流式）
            else
            {
              // 这不是真正的流式访问，可能是反复访问同一位置
              MR.IsStreamAccess = false;
            }
          }
        }
      }
    }

    // ===== LoopAccessInfo 的 symbolic stride 判定 =====
    if (LAI)
    {
      auto &StrideMap = LAI->getSymbolicStrides();
      auto It = StrideMap.find(PtrOperand);
      if (It != StrideMap.end())
      {
        MR.IsStreamAccess = true;
        MR.StreamScore += StreamBonus * 0.6;
        base += StreamBonus * 0.6;
      }
    }

    // ===== 多维数组访问分析 =====
    if (auto *GEP = dyn_cast<GetElementPtrInst>(PtrOperand))
    {
      // 检查是否是多维数组访问
      if (GEP->getNumIndices() > 1)
      {
        bool IsRowMajor = true;
        bool IsColumnMajor = true;
        bool HasVariableIndex = false;

        // 检查索引变化模式
        for (unsigned i = 0; i < GEP->getNumIndices(); ++i)
        {
          Value *Idx = GEP->getOperand(i + 1);

          if (!isa<ConstantInt>(Idx))
          {
            HasVariableIndex = true;

            if (SE.isSCEVable(Idx->getType()))
            {
              const SCEV *IdxSCEV = SE.getSCEV(Idx);

              // 变化最快的应该是最后一个索引（行优先）或第一个索引（列优先）
              if (i == GEP->getNumIndices() - 1)
              {
                // 最后一个索引应该变化最快
                if (!isa<SCEVAddRecExpr>(IdxSCEV) ||
                    !cast<SCEVAddRecExpr>(IdxSCEV)->isAffine())
                {
                  IsRowMajor = false;
                }
              }
              else if (i == 0)
              {
                // 第一个索引应该变化最快（列优先）
                if (!isa<SCEVAddRecExpr>(IdxSCEV) ||
                    !cast<SCEVAddRecExpr>(IdxSCEV)->isAffine())
                {
                  IsColumnMajor = false;
                }
              }
              else
              {
                // 中间索引应该变化较慢
                if (isa<SCEVAddRecExpr>(IdxSCEV) &&
                    cast<SCEVAddRecExpr>(IdxSCEV)->isAffine())
                {
                  // 如果中间索引变化较快，可能是非最优访问模式
                  double penalty = (GEP->getNumIndices() - i) * 0.5;
                  base -= penalty;
                  MR.ChaosPenalty += penalty;
                }
              }
            }
          }
        }

        // 行优先访问模式（C/C++标准）奖励
        if (HasVariableIndex && IsRowMajor)
        {
          MR.IsStreamAccess = true;
          MR.StreamScore += StreamBonus * 0.8;
          base += StreamBonus * 0.8;
        }
        // 列优先访问模式（Fortran标准）
        else if (HasVariableIndex && IsColumnMajor)
        {
          // 列优先访存在C/C++中不常见，但是合法的流式访问
          MR.IsStreamAccess = true;
          MR.StreamScore += StreamBonus * 0.6;
          base += StreamBonus * 0.6;
        }
      }
    }

    // ===== 向量化潜力判定 =====
    if (LAI && LAI->getMaxSafeDepDistBytes() != (unsigned)-1)
    {
      MR.IsVectorized = true;
      MR.VectorScore += VectorBonus;
      base += VectorBonus;
    }

    // ===== 向量化metadata标记判定 =====
    if (isLoopMarkedVectorizable(L))
    {
      MR.IsVectorized = true;
      MR.VectorScore += VectorBonus;
      base += VectorBonus;
    }

    // ===== 并行化分析 =====
    if (MR.IsParallel)
    {
      bool IsLoopSafe = LAI && LAI->isDependencySafe();
      bool MarkedParallel = isMarkedParallel(L);
      bool ThreadPartitioned = PtrOperand && isThreadIDRelated(PtrOperand);

      if ((IsLoopSafe || MarkedParallel) && ThreadPartitioned)
      {
        MR.IsThreadPartitioned = true;
        MR.ParallelScore += ParallelBonus * 1.5;
        base += ParallelBonus * 1.5;
      }
      else if (IsLoopSafe || MarkedParallel)
      {
        MR.MayConflict = true;
        MR.ConflictPenalty += ParallelBonus * 0.5;
        base -= ParallelBonus * 0.5;
      }
      else
      {
        MR.MayConflict = true;
        MR.ConflictPenalty += ParallelBonus;
        base -= ParallelBonus;
      }
    }
  }

  // ===== 混乱度评分 =====
  MR.ChaosPenalty = computeAccessChaosScore(PtrOperand, MSSA, SE);
  base -= MR.ChaosPenalty;

  // ===== 静态得分计算 =====
  double score = base * (depth + 1) * std::sqrt((double)tripCount);
  MR.Score = score;
  if (MR.IsParallel)
    score += ParallelBonus;
  if (MR.IsVectorized)
    score += VectorBonus;
  if (MR.IsStreamAccess)
    score += StreamBonus;

  // ===== 动态 profile 融合校正评分 =====
  if (MR.DynamicAccessCount > 0)
  {
    double dynamicWeight = std::log((double)MR.DynamicAccessCount + 1.0);

    // 若静态判定为混乱，但运行热度很高 → 加回一定权重
    if (MR.ChaosScore > 2.0 && dynamicWeight > 10.0)
    {
      score += dynamicWeight * 0.3; // 补偿
      MR.WasDynamicHotButStaticLow = true;
    }

    // 若静态分高，但动态访问极少 → 说明是伪热点
    if (score > 50.0 && dynamicWeight < 5.0)
    {
      score -= 10.0; // 降权
      MR.WasStaticHotButDynamicCold = true;
    }

    // 若 MemorySSA结构复杂，但运行时确实频繁访问，也应部分补偿
    if (MR.SSAPenalty > 2.0 && dynamicWeight > 10.0)
    {
      score += 2.0;
    }
  }
  MR.Score = score;
  return score;
}

// 辅助函数，检查值是否可能从内存加载
bool MyFunctionAnalysisPass::isMayLoadFromMemory(Value *V)
{
  if (!V)
    return false;

  if (isa<LoadInst>(V))
    return true;
  if (isa<CallInst>(V) || isa<InvokeInst>(V))
    return true;

  if (auto *I = dyn_cast<Instruction>(V))
  {
    for (Use &U : I->operands())
    {
      if (isMayLoadFromMemory(U.get()))
        return true;
    }
  }

  return false;
}

// 检查指令是否使用向量类型或SIMD操作
bool MyFunctionAnalysisPass::isVectorizedInstruction(Instruction *I)
{
  if (!I)
    return false;

  // 检查直接的向量类型操作
  if (I->getType()->isVectorTy())
    return true;

  // 检查操作数是否为向量类型
  for (unsigned i = 0; i < I->getNumOperands(); ++i)
  {
    if (I->getOperand(i)->getType()->isVectorTy())
      return true;
  }

  // 检查是否为向量内部函数调用
  if (auto *Call = dyn_cast<CallInst>(I))
  {
    Function *Callee = Call->getCalledFunction();
    if (Callee)
    {
      StringRef Name = Callee->getName();
      // 检查LLVM向量内部函数
      if (Name.startswith("llvm.vector") ||
          Name.contains("simd") ||
          Name.contains("vector") ||
          Name.startswith("llvm.x86.sse") ||
          Name.startswith("llvm.x86.avx") ||
          Name.startswith("llvm.x86.mmx") ||
          Name.startswith("llvm.arm.neon"))
        return true;
    }
  }

  // 检查常见向量指令模式
  unsigned Opcode = I->getOpcode();
  if (Opcode == Instruction::ExtractElement ||
      Opcode == Instruction::InsertElement ||
      Opcode == Instruction::ShuffleVector)
    return true;

  return false;
}

// 获取向量类型的宽度
int MyFunctionAnalysisPass::getVectorWidth(Type *Ty)
{
  if (!Ty || !Ty->isVectorTy())
    return 0;
  return cast<VectorType>(Ty)->getElementCount().getKnownMinValue();
}

// 检测函数中是否有SIMD内部函数调用
bool MyFunctionAnalysisPass::detectSIMDIntrinsics(Function &F)
{
  for (auto &BB : F)
  {
    for (auto &I : BB)
    {
      if (auto *Call = dyn_cast<CallInst>(&I))
      {
        Function *Callee = Call->getCalledFunction();
        if (!Callee)
          continue;

        StringRef Name = Callee->getName();
        // 检查常见SIMD内部函数
        if (Name.startswith("llvm.x86.sse") ||
            Name.startswith("llvm.x86.avx") ||
            Name.startswith("llvm.x86.mmx") ||
            Name.startswith("llvm.arm.neon") ||
            Name.startswith("_mm_") ||    // Intel SSE
            Name.startswith("_mm256_") || // Intel AVX
            Name.startswith("_mm512_") || // Intel AVX-512
            Name.startswith("vec_"))      // PowerPC Altivec
          return true;
      }
    }
  }
  return false;
}

// 检查循环是否显示出向量化模式
bool MyFunctionAnalysisPass::isVectorLoopPattern(Loop *L, ScalarEvolution &SE)
{
  if (!L)
    return false;

  BasicBlock *Header = L->getHeader();
  if (!Header)
    return false;

  // 1. 检查循环是否被向量化注解标记
  if (isLoopMarkedVectorizable(L))
    return true;

  // 2. 循环访问步长检查 - 连续步长通常更容易向量化
  bool HasConsecutiveAccess = false;
  for (auto &BB : *L)
  {
    for (auto &I : *BB)
    {
      if (auto *Load = dyn_cast<LoadInst>(&I))
      {
        if (SE.isSCEVable(Load->getPointerOperand()->getType()))
        {
          const SCEV *PtrSCEV = SE.getSCEV(Load->getPointerOperand());
          if (auto *AR = dyn_cast<SCEVAddRecExpr>(PtrSCEV))
          {
            if (AR->isAffine() &&
                isa<SCEVConstant>(AR->getStepRecurrence(SE)))
            {
              HasConsecutiveAccess = true;
            }
          }
        }
      }
      else if (auto *Store = dyn_cast<StoreInst>(&I))
      {
        if (SE.isSCEVable(Store->getPointerOperand()->getType()))
        {
          const SCEV *PtrSCEV = SE.getSCEV(Store->getPointerOperand());
          if (auto *AR = dyn_cast<SCEVAddRecExpr>(PtrSCEV))
          {
            if (AR->isAffine() &&
                isa<SCEVConstant>(AR->getStepRecurrence(SE)))
            {
              HasConsecutiveAccess = true;
            }
          }
        }
      }
    }
  }

  // 3. 循环体大小 - 小循环体更容易向量化
  unsigned LoopSize = 0;
  for (auto *BB : L->getBlocks())
  {
    LoopSize += std::distance(BB->begin(), BB->end());
  }
  bool IsSmallLoopBody = LoopSize < 50; // 经验阈值，可调整

  // 4. 检查循环内是否有影响向量化的分支
  bool HasBranches = false;
  for (auto *BB : L->getBlocks())
  {
    if (BB != L->getHeader() && BB != L->getExitingBlock() &&
        isa<BranchInst>(BB->getTerminator()) &&
        cast<BranchInst>(BB->getTerminator())->isConditional())
    {
      HasBranches = true;
      break;
    }
  }

  // 5. 循环内的归约操作检查 - 典型的可向量化模式
  bool HasReduction = false;
  for (auto *BB : L->getBlocks())
  {
    for (auto &I : *BB)
    {
      if (I.getOpcode() == Instruction::Add ||
          I.getOpcode() == Instruction::FAdd ||
          I.getOpcode() == Instruction::Mul ||
          I.getOpcode() == Instruction::FMul)
      {
        for (auto &Op : I.operands())
        {
          if (auto *Inst = dyn_cast<Instruction>(Op.get()))
          {
            if (Inst->getParent() == BB &&
                Inst->getOpcode() == I.getOpcode())
            {
              HasReduction = true;
              break;
            }
          }
        }
        if (HasReduction)
          break;
      }
    }
    if (HasReduction)
      break;
  }

  // 综合评估是否是向量化友好的循环
  return HasConsecutiveAccess && IsSmallLoopBody && !HasBranches || HasReduction;
}

// 递归检查值是否参与了向量操作
bool MyFunctionAnalysisPass::hasVectorOperations(Value *V, std::set<Value *> &Visited)
{
  if (!V || !Visited.insert(V).second)
    return false;

  // 检查值是否为向量类型
  if (V->getType()->isVectorTy())
    return true;

  // 检查指令是否为向量指令
  if (auto *I = dyn_cast<Instruction>(V))
  {
    if (isVectorizedInstruction(I))
      return true;

    // 递归检查所有使用这个值的指令
    for (auto *User : V->users())
    {
      if (hasVectorOperations(User, Visited))
        return true;
    }

    // 递归检查所有操作数
    for (unsigned i = 0; i < I->getNumOperands(); ++i)
    {
      if (hasVectorOperations(I->getOperand(i), Visited))
        return true;
    }
  }

  return false;
}

// 添加到 MyFunctionAnalysisPass.cpp

// 分析指针的线程访问模式
ThreadAccessPattern MyFunctionAnalysisPass::analyzeThreadAccess(Value *Ptr, Instruction *I)
{
  if (!Ptr || !I)
    return ThreadAccessPattern::UNKNOWN;

  Function *F = I->getFunction();
  if (!F || !detectParallelRuntime(*F))
    return ThreadAccessPattern::UNKNOWN; // 非并行函数

  // 是否是原子访问
  if (isAtomicAccess(I))
    return ThreadAccessPattern::ATOMIC_ACCESS;

  // 检查是否通过线程ID索引
  if (isThreadDependentAccess(Ptr))
    return ThreadAccessPattern::PARTITIONED;

  // 检查是否只读共享
  bool isWrite = false;
  if (isa<StoreInst>(I))
    isWrite = true;
  else if (auto *Call = dyn_cast<CallInst>(I))
  {
    // 检查调用是否可能写入内存
    if (Call->mayWriteToMemory())
      isWrite = true;
  }

  if (!isWrite)
  {
    // 只读访问通常是安全的
    return ThreadAccessPattern::SHARED_READONLY;
  }

  // 检查是否存在伪共享
  const DataLayout &DL = I->getModule()->getDataLayout();
  if (detectFalseSharing(Ptr, DL))
    return ThreadAccessPattern::FALSE_SHARING;

  // 默认为共享写入访问（可能有冲突）
  return ThreadAccessPattern::SHARED_WRITE;
}

// 检测是否为原子访问
bool MyFunctionAnalysisPass::isAtomicAccess(Instruction *I)
{
  if (!I)
    return false;

  // 显式原子指令
  if (isa<AtomicRMWInst>(I) || isa<AtomicCmpXchgInst>(I))
    return true;

  // 检查Load/Store是否为原子操作
  if (auto *Load = dyn_cast<LoadInst>(I))
    return Load->isAtomic();
  if (auto *Store = dyn_cast<StoreInst>(I))
    return Store->isAtomic();

  // 检查是否调用原子操作函数
  if (auto *Call = dyn_cast<CallInst>(I))
  {
    Function *Callee = Call->getCalledFunction();
    if (Callee)
    {
      StringRef Name = Callee->getName();
      return Name.contains("atomic") ||
             Name.contains("mutex") ||
             Name.contains("lock") ||
             Name.contains("sync");
    }
  }

  return false;
}

// 检测是否为OpenMP并行执行
bool MyFunctionAnalysisPass::isOpenMPParallel(Function &F)
{
  // 检查函数名称或属性
  if (F.getName().contains("_omp_") ||
      F.hasFnAttribute("omp") ||
      F.getSection().contains("omp"))
    return true;

  // 检查是否调用OpenMP运行时函数
  for (auto &BB : F)
  {
    for (auto &I : BB)
    {
      if (auto *Call = dyn_cast<CallInst>(&I))
      {
        Function *Callee = Call->getCalledFunction();
        if (Callee)
        {
          StringRef Name = Callee->getName();
          if (Name.startswith("__kmpc_") ||
              Name.startswith("omp_") ||
              Name.contains("gomp"))
            return true;
        }
      }
    }
  }

  // 检查OpenMP元数据
  for (auto &BB : F)
  {
    for (auto &I : BB)
    {
      if (I.getMetadata("llvm.loop.parallel_accesses"))
        return true;
    }
  }

  return false;
}

// 检测是否为CUDA并行执行
bool MyFunctionAnalysisPass::isCUDAParallel(Function &F)
{
  // 检查函数是否有CUDA属性
  if (F.getName().startswith("_Z") &&
      (F.getName().contains("cuda") ||
       F.hasFnAttribute("kernel") ||
       F.getSection().contains("cuda")))
    return true;

  // 检查是否调用CUDA运行时函数
  for (auto &BB : F)
  {
    for (auto &I : BB)
    {
      if (auto *Call = dyn_cast<CallInst>(&I))
      {
        Function *Callee = Call->getCalledFunction();
        if (Callee)
        {
          StringRef Name = Callee->getName();
          if (Name.startswith("cuda") ||
              Name.contains("kernel") ||
              Name.contains("nvvm"))
            return true;
        }
      }
    }
  }

  return false;
}

// 检测是否为TBB并行执行
bool MyFunctionAnalysisPass::isTBBParallel(Function &F)
{
  // 检查是否调用TBB函数
  for (auto &BB : F)
  {
    for (auto &I : BB)
    {
      if (auto *Call = dyn_cast<CallInst>(&I))
      {
        Function *Callee = Call->getCalledFunction();
        if (Callee)
        {
          StringRef Name = Callee->getName();
          if (Name.contains("tbb") &&
              (Name.contains("parallel") ||
               Name.contains("task") ||
               Name.contains("flow")))
            return true;
        }
      }
    }
  }

  return false;
}

// 估计并行执行的线程数
unsigned MyFunctionAnalysisPass::estimateParallelThreads(Function &F)
{
  // 默认并行度
  unsigned DefaultThreads = 4;

  // 检查显式线程数设置
  for (auto &BB : F)
  {
    for (auto &I : BB)
    {
      if (auto *Call = dyn_cast<CallInst>(&I))
      {
        Function *Callee = Call->getCalledFunction();
        if (!Callee)
          continue;

        StringRef Name = Callee->getName();
        // OpenMP线程数设置
        if (Name == "omp_set_num_threads" && Call->arg_size() > 0)
        {
          if (auto *CI = dyn_cast<ConstantInt>(Call->getArgOperand(0)))
            return CI->getZExtValue();
        }
        // CUDA内核启动
        else if (Name.contains("cudaLaunch") && Call->arg_size() > 1)
        {
          // 尝试提取CUDA网格和块大小
          // 注意：这是一个近似分析，实际情况可能更复杂
          return 32; // 典型CUDA warp大小
        }
        // TBB并行
        else if (Name.contains("tbb::parallel_for") && Call->arg_size() > 1)
        {
          return 8; // 典型TBB默认并行度
        }
      }
    }
  }

  // 检查函数属性中是否指定了线程数
  if (auto *AttrNode = F.getMetadata("parallel.threads"))
  {
    if (AttrNode->getNumOperands() > 0)
    {
      if (auto *ThreadsMD = dyn_cast<ConstantAsMetadata>(AttrNode->getOperand(0)))
      {
        if (auto *CI = dyn_cast<ConstantInt>(ThreadsMD->getValue()))
          return CI->getZExtValue();
      }
    }
  }

  // 根据并行类型估计默认线程数
  if (isOpenMPParallel(F))
    return std::thread::hardware_concurrency(); // 使用硬件核心数
  if (isCUDAParallel(F))
    return 128; // 典型CUDA并行度
  if (isTBBParallel(F))
    return std::thread::hardware_concurrency(); // 使用硬件核心数

  return DefaultThreads;
}

// 检查是否有并行循环元数据
bool MyFunctionAnalysisPass::hasParallelLoopMetadata(Loop *L)
{
  if (!L || !L->getHeader())
    return false;

  Instruction *Term = L->getHeader()->getTerminator();
  if (!Term)
    return false;

  if (MDNode *LoopID = Term->getMetadata("llvm.loop.parallel_accesses"))
    return true;

  if (MDNode *LoopID = Term->getMetadata("llvm.loop"))
  {
    for (unsigned i = 0, e = LoopID->getNumOperands(); i < e; ++i)
    {
      MDNode *MD = dyn_cast<MDNode>(LoopID->getOperand(i));
      if (!MD)
        continue;

      for (unsigned j = 0, je = MD->getNumOperands(); j < je; ++j)
      {
        if (auto *Str = dyn_cast<MDString>(MD->getOperand(j)))
        {
          if (Str->getString().contains("parallel"))
            return true;
        }
      }
    }
  }

  return false;
}

// 检测是否可能存在伪共享
bool MyFunctionAnalysisPass::detectFalseSharing(Value *Ptr, DataLayout &DL)
{
  if (!Ptr)
    return false;

  // 如果是GEP指令，分析其索引模式
  if (auto *GEP = dyn_cast<GetElementPtrInst>(Ptr))
  {
    Value *BasePtr = GEP->getPointerOperand();
    Type *BaseTy = BasePtr->getType()->getPointerElementType();

    // 检查是否为数组或结构体
    if (BaseTy->isArrayTy() || BaseTy->isStructTy())
    {
      // 计算访问的近似内存范围
      unsigned TypeSize = DL.getTypeAllocSize(BaseTy);
      unsigned CacheLineSize = 64; // 典型缓存行大小

      // 如果类型大小小于缓存行，并且多个线程访问同一缓存行的不同部分，
      // 可能存在伪共享
      if (TypeSize < CacheLineSize)
      {
        // 检查GEP的索引是否与线程ID相关（但仍共享同一缓存行）
        for (auto I = GEP->idx_begin(), E = GEP->idx_end(); I != E; ++I)
        {
          if (isThreadIDRelated(*I))
          {
            // 检查索引范围是否可能导致多个线程访问同一缓存行的不同部分
            // 对于简单情况下，我们假设如果索引是线程ID相关的且元素小于缓存行，
            // 就可能存在伪共享
            return true;
          }
        }
      }
    }
  }

  return false;
}

// 检查是否为线程依赖的访问（通过线程ID进行索引）
bool MyFunctionAnalysisPass::isThreadDependentAccess(Value *Ptr)
{
  if (!Ptr)
    return false;

  // 如果是GEP指令，检查其索引是否依赖线程ID
  if (auto *GEP = dyn_cast<GetElementPtrInst>(Ptr))
  {
    for (auto I = GEP->idx_begin(), E = GEP->idx_end(); I != E; ++I)
    {
      Value *Idx = *I;

      // 检查索引是否依赖线程ID
      if (isThreadIDRelated(Idx))
        return true;

      // 递归检查复杂索引表达式
      if (auto *IdxInst = dyn_cast<Instruction>(Idx))
      {
        // 递归检查二元操作的操作数
        if (auto *BinOp = dyn_cast<BinaryOperator>(IdxInst))
        {
          if (isThreadIDRelated(BinOp->getOperand(0)) ||
              isThreadIDRelated(BinOp->getOperand(1)))
            return true;
        }
      }
    }
  }

  return false;
}

// 检查是否为线程安全的访问
bool MyFunctionAnalysisPass::isThreadSafeAccess(Value *Ptr, AAResults &AA)
{
  if (!Ptr)
    return false;

  // 如果是只读访问，通常是安全的
  bool isReadOnly = true;
  for (User *U : Ptr->users())
  {
    if (auto *I = dyn_cast<Instruction>(U))
    {
      if (auto *Store = dyn_cast<StoreInst>(I))
      {
        if (Store->getPointerOperand() == Ptr)
        {
          isReadOnly = false;
          break;
        }
      }
      else if (auto *Call = dyn_cast<CallInst>(I))
      {
        if (Call->mayWriteToMemory() && isPointerAccessedByCall(Call, Ptr, AA))
        {
          isReadOnly = false;
          break;
        }
      }
    }
  }

  if (isReadOnly)
    return true;

  // 如果是线程本地访问，也是安全的
  if (isThreadLocalStorage(Ptr))
    return true;

  // 如果有原子访问，也是线程安全的（但可能有性能开销）
  for (User *U : Ptr->users())
  {
    if (auto *I = dyn_cast<Instruction>(U))
    {
      if (isAtomicAccess(I))
        return true;
    }
  }

  return false;
}

// 辅助函数：检查指针是否被调用指令访问
bool MyFunctionAnalysisPass::isPointerAccessedByCall(CallInst *Call, Value *Ptr, AAResults &AA)
{
  if (!Call || !Ptr)
    return false;

  // 遍历所有参数
  for (unsigned i = 0; i < Call->arg_size(); ++i)
  {
    Value *Arg = Call->getArgOperand(i);
    if (!Arg->getType()->isPointerTy())
      continue;

    // 检查参数是否可能指向与Ptr相同的内存
    AliasResult AR = AA.alias(Arg, Ptr);
    if (AR != AliasResult::NoAlias)
      return true;
  }

  return false;
}

// 辅助函数：检查是否为线程本地存储
bool MyFunctionAnalysisPass::isThreadLocalStorage(Value *Ptr)
{
  if (!Ptr)
    return false;

  // 检查是否为线程本地变量
  if (auto *GV = dyn_cast<GlobalVariable>(Ptr))
    return GV->isThreadLocal();

  // 检查是否为局部变量（栈上分配，通常是线程本地的）
  if (isa<AllocaInst>(Ptr))
    return true;

  // 检查是否显式标记为线程本地
  if (auto *I = dyn_cast<Instruction>(Ptr))
  {
    if (I->getMetadata("thread_local"))
      return true;
  }

  return false;
}

uint64_t MyFunctionAnalysisPass::getLoopTripCount(Loop *L, ScalarEvolution &SE)
{
  if (!L)
    return 1;
  const SCEV *BEC = SE.getBackedgeTakenCount(L);
  if (auto *SC = dyn_cast<SCEVConstant>(BEC))
  {
    const APInt &val = SC->getAPInt();
    if (!val.isMaxValue())
      return val.getZExtValue() + 1;
  }
  return 1;
}

// 分析数据访问的局部性
LocalityType MyFunctionAnalysisPass::analyzeDataLocality(Value *Ptr, Loop *L, ScalarEvolution &SE)
{
  if (!Ptr || !L || !SE.isSCEVable(Ptr->getType()))
    return LocalityType::MODERATE; // 默认中等局部性

  const SCEV *PtrSCEV = SE.getSCEV(Ptr);

  // 检查空间局部性 - 连续访问有良好的空间局部性
  bool hasGoodSpatialLocality = false;
  bool hasGoodTemporalLocality = false;

  if (auto *AR = dyn_cast<SCEVAddRecExpr>(PtrSCEV))
  {
    if (AR->isAffine())
    {
      if (auto *Step = dyn_cast<SCEVConstant>(AR->getStepRecurrence(SE)))
      {
        int64_t StepVal = Step->getValue()->getSExtValue();

        // 小步长意味着连续访问，空间局部性好
        if (StepVal == 1 || StepVal == -1 || StepVal == 2 || StepVal == -2 || StepVal == 4 || StepVal == -4 || StepVal == 8 || StepVal == -8)
        {
          hasGoodSpatialLocality = true;
        }
      }
    }
  }

  // 检查时间局部性 - 在相对短的时间内重复访问同一数据
  // 简单方法：检查是否在嵌套循环中
  unsigned loopNestDepth = 0;
  Loop *CurLoop = L;
  while (CurLoop)
  {
    loopNestDepth++;
    CurLoop = CurLoop->getParentLoop();
  }

  // 嵌套循环中可能存在时间局部性
  if (loopNestDepth >= 2)
  {
    // 检查更详细的模式...

    // 检查是否有循环不变量逗留在内层循环中
    for (auto *BB : L->getBlocks())
    {
      for (auto &I : *BB)
      {
        if (auto *LI = dyn_cast<LoadInst>(&I))
        {
          Value *LoadPtr = LI->getPointerOperand();
          if (LoadPtr == Ptr)
            continue; // 跳过当前分析的指针

          if (SE.isSCEVable(LoadPtr->getType()))
          {
            const SCEV *LoadSCEV = SE.getSCEV(LoadPtr);
            if (SE.isLoopInvariant(LoadSCEV, L))
            {
              // 该Load在当前循环中是循环不变量，可能被多次访问
              hasGoodTemporalLocality = true;
            }
          }
        }
      }
    }
  }

  // 基于空间和时间局部性综合评估
  if (hasGoodSpatialLocality && hasGoodTemporalLocality)
  {
    return LocalityType::EXCELLENT;
  }
  else if (hasGoodSpatialLocality)
  {
    return LocalityType::GOOD;
  }
  else if (hasGoodTemporalLocality)
  {
    return LocalityType::MODERATE;
  }
  else
  {
    return LocalityType::POOR;
  }
}

bool MyFunctionAnalysisPass::detectParallelRuntime(Function &F)
{
  const std::unordered_set<std::string> ParallelEntrypoints = {
      "__kmpc_fork_call", "__kmpc_for_static_init_4", "__kmpc_for_static_init_8",
      "__kmpc_for_static_init_16", "__kmpc_for_static_init_32", "__kmpc_for_static_init_64",
      "__kmpc_push_num_threads", "__kmpc_barrier",
      "pthread_create", "pthread_join", "pthread_mutex_lock", "pthread_mutex_unlock",
      "_ZSt13__thread_call", "std::thread",
      "tbb::task_group::run", "tbb::parallel_for", "tbb::parallel_invoke",
      "clEnqueueNDRangeKernel", "cudaLaunch", "cudaMemcpyAsync"};

  for (auto &BB : F)
  {
    for (auto &I : BB)
    {
      if (auto *CI = dyn_cast<CallInst>(&I))
      {
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

// 分析Profile数据
ProfileGuidedInfo MyFunctionAnalysisPass::analyzeProfileData(CallInst *MallocCall, Function &F)
{
  ProfileGuidedInfo Result;
  if (!MallocCall)
    return Result;

  // 检查是否有Profile元数据
  bool hasMetadata = false;
  if (MDNode *ProfMD = MallocCall->getMetadata("prof.memusage"))
  {
    hasMetadata = true;
    Result.hasProfileData = true;

    // 提取内存使用频率数据
    if (ProfMD->getNumOperands() > 0)
    {
      if (auto *Op = dyn_cast<ConstantAsMetadata>(ProfMD->getOperand(0)))
      {
        if (auto *CInt = dyn_cast<ConstantInt>(Op->getValue()))
        {
          uint64_t usage = CInt->getZExtValue();
          Result.dynamicWeight = std::log2(double(usage) + 1.0) / 20.0; // 归一化
        }
      }
    }
  }

  // 检查基于块频率的额外Profile信息
  if (MDNode *BlockFreqMD = F.getMetadata("prof.block.frequency"))
  {
    Result.hasProfileData = true;

    // 找到malloc所在的基本块
    BasicBlock *MallocBB = MallocCall->getParent();

    // 检查该基本块是否是热点
    if (F.getEntryCount().hasValue())
    {
      auto EntryCount = F.getEntryCount().getValue();

      // 如果有基本块执行计数
      if (BlockFreqMD->getNumOperands() > 0)
      {
        for (unsigned i = 0; i < BlockFreqMD->getNumOperands(); ++i)
        {
          auto *BlockFreqPair = dyn_cast<MDNode>(BlockFreqMD->getOperand(i));
          if (!BlockFreqPair || BlockFreqPair->getNumOperands() < 2)
            continue;

          // 提取基本块ID和频率
          if (auto *BBMD = dyn_cast<ValueAsMetadata>(BlockFreqPair->getOperand(0)))
          {
            if (auto *BB = dyn_cast<BasicBlock>(BBMD->getValue()))
            {
              if (BB == MallocBB)
              {
                if (auto *FreqMD = dyn_cast<ConstantAsMetadata>(BlockFreqPair->getOperand(1)))
                {
                  if (auto *Freq = dyn_cast<ConstantInt>(FreqMD->getValue()))
                  {
                    // 计算该基本块的热度相对于入口块
                    uint64_t BBCount = Freq->getZExtValue();
                    double relativeHeat = double(BBCount) / double(EntryCount);

                    Result.hotspotHints.push_back(
                        {"block_relative_heat", relativeHeat});

                    // 根据热度调整动态权重
                    Result.dynamicWeight = std::max(Result.dynamicWeight, relativeHeat * 0.5);
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  // 分析主循环出现的频率
  for (auto &BB : F)
  {
    for (auto &I : BB)
    {
      if (auto *CI = dyn_cast<CallInst>(&I))
      {
        // 检查是否有与特定循环相关的Profile注解
        if (CI->getMetadata("prof.loop.iterations"))
        {
          // 找到迭代次数很多的循环
          MDNode *LoopMD = CI->getMetadata("prof.loop.iterations");
          if (LoopMD->getNumOperands() > 0)
          {
            if (auto *IterMD = dyn_cast<ConstantAsMetadata>(LoopMD->getOperand(0)))
            {
              if (auto *Iters = dyn_cast<ConstantInt>(IterMD->getValue()))
              {
                uint64_t iterations = Iters->getZExtValue();

                // 高迭代次数的循环是潜在热点
                if (iterations > 1000)
                {
                  Result.hotspotHints.push_back(
                      {"high_iteration_loop", double(iterations) / 10000.0});
                }
              }
            }
          }
        }
      }
    }
  }

  // 基于静态vs动态结果的一致性计算信心度
  if (Result.hasProfileData)
  {
    // 假设我们之前计算了静态分数，范围是0-100
    // 我们检查静态和动态结果是否一致

    // 例如，如果MallocCall周围有很多LoadInst/StoreInst，
    // 但动态Profile显示使用频率低，则降低信心
    unsigned staticMemOpCount = 0;
    BasicBlock *BB = MallocCall->getParent();
    for (auto &I : *BB)
    {
      if (isa<LoadInst>(I) || isa<StoreInst>(I))
      {
        staticMemOpCount++;
      }
    }

    if (staticMemOpCount > 5 && Result.dynamicWeight < 0.2)
    {
      // 静态分析显示内存操作多，但动态访问少
      Result.staticConfidence = 0.5; // 降低信心
    }
    else if (staticMemOpCount < 3 && Result.dynamicWeight > 0.5)
    {
      // 静态分析显示内存操作少，但动态访问多
      Result.staticConfidence = 0.6; // 适当降低信心
    }
    else
    {
      // 静态和动态分析基本一致
      Result.staticConfidence = 0.8; // 较高信心
    }
  }
  else
  {
    // 没有Profile数据时，默认中等信心
    Result.staticConfidence = 0.7;
  }

  return Result;
}

// 使用Profile数据调整分数
double MyFunctionAnalysisPass::adjustScoreWithProfile(double staticScore, const ProfileGuidedInfo &PGI)
{
  if (!PGI.hasProfileData)
  {
    return staticScore; // 没有Profile数据时不调整
  }

  double adjustedScore = staticScore;

  // 根据信心度混合静态和动态分数
  if (PGI.dynamicWeight > 0.0)
  {
    // 使用动态权重估算动态分数 (0-100范围)
    double dynamicScore = PGI.dynamicWeight * 100.0;

    // 混合静态和动态分数，基于信心度
    adjustedScore = staticScore * PGI.staticConfidence +
                    dynamicScore * (1.0 - PGI.staticConfidence);
  }

  // 应用额外的热点提示
  for (const auto &hint : PGI.hotspotHints)
  {
    if (hint.first == "block_relative_heat" && hint.second > 0.5)
    {
      // 如果基本块是热点，提高分数
      adjustedScore *= (1.0 + hint.second * 0.3);
    }
    else if (hint.first == "high_iteration_loop" && hint.second > 0.1)
    {
      // 如果在高迭代次数循环中，提高分数
      adjustedScore *= (1.0 + hint.second * 0.5);
    }
  }

  return adjustedScore;
}

// 计算自适应阈值
AdaptiveThresholdInfo MyFunctionAnalysisPass::computeAdaptiveThreshold(Module &M,
                                                                       const std::vector<MallocRecord> &AllMallocs)
{
  AdaptiveThresholdInfo Result;

  // 默认基础阈值
  Result.baseThreshold = MyHBMOptions::HBMThreshold;
  Result.adjustedThreshold = Result.baseThreshold;

  // 没有数据时返回默认值
  if (AllMallocs.empty())
  {
    Result.adjustmentReason = "Using default threshold due to no malloc records";
    return Result;
  }

  // 1. 分析分数分布
  std::vector<double> Scores;
  double TotalScore = 0.0;
  double MaxScore = 0.0;
  uint64_t TotalSize = 0;

  for (const auto &MR : AllMallocs)
  {
    Scores.push_back(MR.Score);
    TotalScore += MR.Score;
    MaxScore = std::max(MaxScore, MR.Score);
    TotalSize += MR.AllocSize;
  }

  // 计算分数的平均值和标准差
  double MeanScore = TotalScore / Scores.size();

  double Variance = 0.0;
  for (double score : Scores)
  {
    Variance += (score - MeanScore) * (score - MeanScore);
  }
  Variance /= Scores.size();
  double StdDev = std::sqrt(Variance);

  // 2. 根据程序特性调整阈值

  // 检查HBM容量限制
  uint64_t HBMCapacity = 1ULL << 30; // 默认1GB
  double SizeRatio = (double)TotalSize / HBMCapacity;

  if (SizeRatio > 0.8)
  {
    // 总分配大小接近或超过HBM容量，提高阈值
    double increaseFactor = std::min(1.5, 0.5 + SizeRatio);
    Result.adjustedThreshold = Result.baseThreshold * increaseFactor;
    Result.adjustmentReason = "Increased threshold due to large total allocation size";
    return Result;
  }

  // 检查分数分布
  if (StdDev < 10.0 && MeanScore > 30.0)
  {
    // 所有分数比较接近，且平均较高，降低阈值
    Result.adjustedThreshold = std::max(30.0, MeanScore - StdDev);
    Result.adjustmentReason = "Decreased threshold due to clustered high scores";
  }
  else if (StdDev > 30.0)
  {
    // 分数分布很分散，使用统计方法找出合适的阈值
    // 例如，使用平均值+0.5*标准差
    Result.adjustedThreshold = MeanScore + 0.5 * StdDev;
    Result.adjustmentReason = "Adjusted threshold based on score distribution";
  }
  else if (MaxScore < 60.0)
  {
    // 最高分都不太高，适当降低阈值
    Result.adjustedThreshold = std::max(30.0, MaxScore * 0.8);
    Result.adjustmentReason = "Decreased threshold due to overall low scores";
  }

  // 3. 检查模块特性
  bool HasParallelCode = false;
  bool HasVectorizedCode = false;

  for (auto &F : M)
  {
    // 检查是否有并行或向量化特征
    if (F.hasFnAttribute("parallel") || F.getName().contains("parallel"))
    {
      HasParallelCode = true;
    }
    if (F.hasFnAttribute("vector") || F.getName().contains("simd"))
    {
      HasVectorizedCode = true;
    }
  }

  // 根据程序特性最后调整
  if (HasParallelCode && HasVectorizedCode)
  {
    // 并行+向量化代码更可能从HBM受益，降低阈值
    Result.adjustedThreshold *= 0.8;
    Result.adjustmentReason += ", further decreased for parallel+vectorized code";
  }
  else if (!HasParallelCode && !HasVectorizedCode)
  {
    // 既不并行也不向量化，提高阈值
    Result.adjustedThreshold *= 1.2;
    Result.adjustmentReason += ", increased for sequential scalar code";
  }

  // 确保阈值在合理范围内
  Result.adjustedThreshold = std::max(20.0, std::min(80.0, Result.adjustedThreshold));

  return Result;
}

// 计算多维度评分
MultiDimensionalScore MyFunctionAnalysisPass::computeMultiDimensionalScore(const MallocRecord &MR)
{
  MultiDimensionalScore Result;

  // 1. 带宽需求得分 - 基于流式/向量化/并行特性
  double bandwidthBase = 0.0;

  // 加权考虑各种带宽影响因素
  if (MR.IsStreamAccess)
    bandwidthBase += 30.0;
  if (MR.IsVectorized)
    bandwidthBase += 20.0;
  if (MR.IsParallel)
  {
    if (MR.IsThreadPartitioned)
    {
      bandwidthBase += 25.0; // 良好的并行分区
    }
    else if (MR.MayConflict)
    {
      bandwidthBase += 10.0; // 有冲突的并行
    }
    else
    {
      bandwidthBase += 15.0; // 一般并行
    }
  }

  // 考虑循环深度和迭代次数
  double loopFactor = 1.0;
  if (MR.LoopDepth > 0)
  {
    loopFactor += 0.2 * MR.LoopDepth;

    // 考虑循环迭代次数
    if (MR.TripCount > 1)
    {
      loopFactor += 0.3 * std::log2(double(MR.TripCount));
    }
  }

  // 考虑动态访问计数
  double dynamicFactor = 1.0;
  if (MR.DynamicAccessCount > 0)
  {
    dynamicFactor += 0.2 * std::log2(double(MR.DynamicAccessCount + 1) / 1000.0);
  }

  // 计算最终带宽得分
  Result.bandwidthScore = bandwidthBase * loopFactor * dynamicFactor;

  // 2. 延迟敏感度得分 - 基于依赖关系和访问模式
  double latencyBase = 0.0;

  // 非规则访问通常更受延迟影响
  if (!MR.IsStreamAccess)
  {
    latencyBase += 20.0;
  }

  // 复杂的内存访问模式可能表明延迟敏感
  latencyBase += MR.ChaosPenalty * 3.0;

  // MemorySSA结构复杂性可能表明延迟敏感
  latencyBase += MR.SSAPenalty * 4.0;

  // 计算最终延迟得分
  Result.latencyScore = latencyBase * loopFactor;

  // 3. 利用率得分 - 评估HBM带宽利用效率
  double utilizationBase = 50.0; // 默认中等效率

  // 流式访问通常能更好地利用HBM带宽
  if (MR.IsStreamAccess)
  {
    utilizationBase += 20.0;
  }

  // 向量化访问可以提高带宽利用率
  if (MR.IsVectorized)
  {
    utilizationBase += 15.0;
  }

  // 随机访问会降低带宽利用率
  if (MR.ChaosPenalty > 0)
  {
    utilizationBase -= MR.ChaosPenalty * 5.0;
  }

  // 计算最终利用率得分
  Result.utilizationScore = utilizationBase;

  // 4. 大小效率得分 - 考虑分配大小与访问频率的比例
  double sizeEfficiencyBase = 50.0; // 默认中等效率

  if (MR.AllocSize > 0 && MR.DynamicAccessCount > 0)
  {
    // 计算每字节的访问次数
    double accessesPerByte = double(MR.DynamicAccessCount) / MR.AllocSize;

    // 访问密度高的分配效率更高
    if (accessesPerByte > 10.0)
    {
      sizeEfficiencyBase += 30.0;
    }
    else if (accessesPerByte > 1.0)
    {
      sizeEfficiencyBase += 20.0;
    }
    else if (accessesPerByte > 0.1)
    {
      sizeEfficiencyBase += 10.0;
    }
    else
    {
      // 访问密度低，效率不高
      sizeEfficiencyBase -= 10.0;
    }
  }

  // 分配大小过大会降低效率
  if (MR.AllocSize > 100 * 1024 * 1024)
  { // 100MB
    sizeEfficiencyBase -= 20.0;
  }
  else if (MR.AllocSize > 10 * 1024 * 1024)
  { // 10MB
    sizeEfficiencyBase -= 10.0;
  }

  // 计算最终大小效率得分
  Result.sizeEfficiencyScore = sizeEfficiencyBase;

  // 5. 计算最终综合得分
  // 使用加权平均
  Result.finalScore =
      0.4 * Result.bandwidthScore +     // 带宽是最重要的因素
      0.2 * Result.latencyScore +       // 延迟次之
      0.3 * Result.utilizationScore +   // 利用率也很重要
      0.1 * Result.sizeEfficiencyScore; // 大小效率影响相对较小

  return Result;
}

double MyFunctionAnalysisPass::computeBandwidthScore(uint64_t approximateBytes, double approximateTime)
{
  if (approximateTime <= 0.0)
    approximateTime = 1.0;
  double bwGBs = (double)approximateBytes / (1024.0 * 1024.0 * 1024.0) / approximateTime;
  return bwGBs;
}

std::optional<uint64_t> MyFunctionAnalysisPass::getConstantAllocSize(Value *V, std::set<Value *> &Visited)
{
  if (!V || !Visited.insert(V).second)
    return std::nullopt;

  if (auto *CI = dyn_cast<ConstantInt>(V))
  {
    if (CI->isNegative())
      return std::nullopt;

    return CI->getZExtValue();
  }
  if (auto *CE = dyn_cast<ConstantExpr>(V))
  {
    auto op0 = getConstantAllocSize(CE->getOperand(0), Visited);
    auto op1 = getConstantAllocSize(CE->getOperand(1), Visited);
    if (!op0 || !op1)
      return std::nullopt;

    switch (CE->getOpcode())
    {
    case Instruction::Add:
      return *op0 + *op1;
    case Instruction::Sub:
      return *op0 > *op1 ? std::optional(*op0 - *op1) : std::nullopt;
    case Instruction::Mul:
      return *op0 * *op1;
    case Instruction::UDiv:
      return *op1 != 0 ? std::optional(*op0 / *op1) : std::nullopt;
    case Instruction::Shl:
      return *op0 << *op1;
    case Instruction::And:
      return *op0 & *op1;
    default:
      break;
    }
  }
  return std::nullopt;
}

// 分析嵌套循环的访存特性
double MyFunctionAnalysisPass::analyzeNestedLoops(Loop *L, Value *Ptr,
                                                  ScalarEvolution &SE,
                                                  LoopAnalysis::Result &LA)
{
  if (!L || !Ptr)
    return 0.0;

  // 计算循环嵌套深度
  unsigned nestDepth = 1;
  Loop *Parent = L->getParentLoop();
  while (Parent)
  {
    nestDepth++;
    Parent = Parent->getParentLoop();
  }

  // 收集所有嵌套循环
  SmallVector<Loop *, 4> LoopHierarchy;
  Loop *CurLoop = L;
  LoopHierarchy.push_back(CurLoop);
  while ((CurLoop = CurLoop->getParentLoop()))
  {
    LoopHierarchy.push_back(CurLoop);
  }

  // 分析每层循环的迭代范围和步长
  double totalScore = 0.0;
  uint64_t estimatedAccesses = 1;
  bool hasRowMajorAccess = false;
  bool hasColumnMajorAccess = false;

  // 从外层到内层分析
  std::reverse(LoopHierarchy.begin(), LoopHierarchy.end());
  for (unsigned i = 0; i < LoopHierarchy.size(); ++i)
  {
    Loop *CurL = LoopHierarchy[i];
    uint64_t tripCount = getLoopTripCount(CurL, SE);
    if (tripCount == 0 || tripCount == (uint64_t)-1)
      tripCount = 100; // 默认估计

    estimatedAccesses *= tripCount;

    // 检查该层循环是否有与Ptr相关的内存访问
    bool hasMemAccess = false;
    for (auto *BB : CurL->getBlocks())
    {
      for (auto &I : *BB)
      {
        if (auto *LI = dyn_cast<LoadInst>(&I))
        {
          if (SE.isSCEVable(LI->getPointerOperand()->getType()))
          {
            const SCEV *PtrSCEV = SE.getSCEV(LI->getPointerOperand());
            // 检查该访问是否与传入的Ptr相关
            if (SE.isLoopInvariant(PtrSCEV, CurL))
            {
              // 该访问在此循环中是循环不变量
              continue;
            }
            hasMemAccess = true;

            // 分析多维数组访问模式
            if (auto *GEP = dyn_cast<GetElementPtrInst>(LI->getPointerOperand()))
            {
              if (GEP->getNumIndices() > 1)
              {
                // 检查不同维度的索引是在哪个循环层变化
                for (unsigned idx = 0; idx < GEP->getNumIndices(); ++idx)
                {
                  Value *IdxOp = GEP->getOperand(idx + 1);
                  if (!SE.isSCEVable(IdxOp->getType()))
                    continue;

                  const SCEV *IdxSCEV = SE.getSCEV(IdxOp);
                  if (!SE.isLoopInvariant(IdxSCEV, CurL))
                  {
                    // 该索引在此循环中变化
                    if (idx == GEP->getNumIndices() - 1 && i == LoopHierarchy.size() - 1)
                    {
                      // 最内层循环访问最后一个维度 - 行优先
                      hasRowMajorAccess = true;
                    }
                    else if (idx == 0 && i == LoopHierarchy.size() - 1)
                    {
                      // 最内层循环访问第一个维度 - 列优先
                      hasColumnMajorAccess = true;
                    }
                  }
                }
              }
            }
          }
        }
        else if (auto *SI = dyn_cast<StoreInst>(&I))
        {
          // 类似的对Store指令进行分析
          // ...
        }
      }
    }

    if (hasMemAccess)
    {
      // 该层循环有相关内存访问，计算分数
      double loopScore = 1.0;

      // 最内层循环权重最高
      if (i == LoopHierarchy.size() - 1)
      {
        loopScore *= 2.0;
      }

      // 嵌套很深的循环权重高
      if (LoopHierarchy.size() >= 3)
      {
        loopScore *= 1.5;
      }

      totalScore += loopScore;
    }
  }

  // 基于访问模式调整分数
  if (hasRowMajorAccess)
  {
    totalScore *= 1.2; // 行优先模式通常效率高
  }
  else if (hasColumnMajorAccess)
  {
    totalScore *= 0.8; // 列优先模式可能效率较低
  }

  // 考虑总的访问次数
  double accessFactor = std::log2(estimatedAccesses + 1) / 10.0;
  totalScore *= (1.0 + accessFactor);

  return totalScore;
}

// 检查循环是否为内存密集型
bool MyFunctionAnalysisPass::isMemoryIntensiveLoop(Loop *L)
{
  if (!L)
    return false;

  unsigned memOpCount = 0;
  unsigned totalOpCount = 0;

  for (auto *BB : L->getBlocks())
  {
    for (auto &I : *BB)
    {
      totalOpCount++;
      if (isa<LoadInst>(I) || isa<StoreInst>(I) ||
          isa<AtomicRMWInst>(I) || isa<AtomicCmpXchgInst>(I) ||
          (isa<CallInst>(I) && cast<CallInst>(I).mayReadOrWriteMemory()))
      {
        memOpCount++;
      }
    }
  }

  // 如果内存操作占比超过30%，认为是内存密集型
  return (totalOpCount > 0) && ((double)memOpCount / totalOpCount > 0.3);
}

// 计算循环嵌套结构得分
double MyFunctionAnalysisPass::computeLoopNestingScore(Loop *L, LoopAnalysis::Result &LA)
{
  if (!L)
    return 0.0;

  double score = 1.0;

  // 检查循环嵌套深度
  unsigned depth = 1;
  Loop *Parent = L->getParentLoop();
  while (Parent)
  {
    depth++;
    Parent = Parent->getParentLoop();
  }

  // 嵌套深度大的循环分数高
  score *= (1.0 + 0.2 * depth);

  // 检查是否包含内存密集型子循环
  unsigned memIntensiveSubLoops = 0;
  for (Loop *SubL : L->getSubLoops())
  {
    if (isMemoryIntensiveLoop(SubL))
    {
      memIntensiveSubLoops++;
    }
  }

  // 有多个内存密集型子循环的循环分数高
  if (memIntensiveSubLoops > 0)
  {
    score *= (1.0 + 0.2 * memIntensiveSubLoops);
  }

  return score;
}

// 分析循环中的交错访问模式
InterleavedAccessInfo MyFunctionAnalysisPass::analyzeInterleavedAccess(Loop *L, ScalarEvolution &SE)
{
  InterleavedAccessInfo Result;
  if (!L)
    return Result;

  // 收集循环中所有的内存访问
  SmallPtrSet<Value *, 16> MemoryAccesses;
  for (auto *BB : L->getBlocks())
  {
    for (auto &I : *BB)
    {
      if (auto *LI = dyn_cast<LoadInst>(&I))
      {
        MemoryAccesses.insert(LI->getPointerOperand());
      }
      else if (auto *SI = dyn_cast<StoreInst>(&I))
      {
        MemoryAccesses.insert(SI->getPointerOperand());
      }
    }
  }

  // 分析这些访问是否是交错模式
  SmallVector<const SCEV *, 8> StridedExprs;
  SmallPtrSet<Value *, 8> BasePointers;

  for (Value *Ptr : MemoryAccesses)
  {
    if (!SE.isSCEVable(Ptr->getType()))
      continue;

    const SCEV *PtrSCEV = SE.getSCEV(Ptr);
    if (auto *AR = dyn_cast<SCEVAddRecExpr>(PtrSCEV))
    {
      if (AR->isAffine())
      {
        StridedExprs.push_back(AR);

        // 尝试识别基地址
        if (auto *GEP = dyn_cast<GetElementPtrInst>(Ptr))
        {
          BasePointers.insert(GEP->getPointerOperand());
        }
      }
    }
  }

  // 检查是否有多个数组以类似的步长访问
  if (StridedExprs.size() >= 2 && BasePointers.size() >= 2)
  {
    Result.isInterleaved = true;
    Result.accessedArrays = BasePointers.size();

    // 计算不同数组之间的步长比率
    if (StridedExprs.size() >= 2)
    {
      // 比较前两个表达式的步长
      auto *FirstStride = cast<SCEVAddRecExpr>(StridedExprs[0])->getStepRecurrence(SE);
      auto *SecondStride = cast<SCEVAddRecExpr>(StridedExprs[1])->getStepRecurrence(SE);

      if (auto *First = dyn_cast<SCEVConstant>(FirstStride))
      {
        if (auto *Second = dyn_cast<SCEVConstant>(SecondStride))
        {
          int64_t FirstVal = First->getValue()->getSExtValue();
          int64_t SecondVal = Second->getValue()->getSExtValue();

          if (FirstVal != 0 && SecondVal != 0)
          {
            Result.strideRatio = (double)std::abs(FirstVal) / std::abs(SecondVal);
          }
        }
      }
    }

    // 如果有多个数组并且步长比率接近1，可能是带宽密集型
    if (Result.accessedArrays >= 2 &&
        Result.strideRatio >= 0.5 && Result.strideRatio <= 2.0)
    {
      Result.isPotentiallyBandwidthBound = true;
    }
  }

  return Result;
}

// 判断是否是常量分配，如果是常量就将分配大小返回
uint64_t MyFunctionAnalysisPass::getConstantAllocSize(Value *V)
{
  std::set<Value *> Visited;
  auto result = getConstantAllocSize(V, Visited);
  return result.value_or(0);
}

// 分析跨函数使用情况
CrossFunctionInfo MyFunctionAnalysisPass::analyzeCrossFunctionUsage(Value *AllocPtr, Module &M)
{
  CrossFunctionInfo Result;
  if (!AllocPtr)
    return Result;

  Result.analyzedCrossFn = true;

  // 获取包含分配指令的函数
  Function *AllocFunc = nullptr;
  if (auto *I = dyn_cast<Instruction>(AllocPtr))
  {
    AllocFunc = I->getFunction();
  }

  if (!AllocFunc)
    return Result;

  // 1. 找出指针传递到的所有函数（被调用函数）
  std::set<Function *> VisitedFuncs;
  trackPointerToFunction(AllocPtr, AllocFunc, VisitedFuncs, Result.calledFunctions);

  // 2. 找出调用者函数（向上追溯）
  VisitedFuncs.clear();
  for (auto &F : M)
  {
    for (auto &BB : F)
    {
      for (auto &I : BB)
      {
        if (auto *Call = dyn_cast<CallInst>(&I))
        {
          // 检查是否调用包含分配的函数
          if (Call->getCalledFunction() == AllocFunc)
          {
            Result.callerFunctions.push_back(&F);
            // 可以进一步递归上溯调用链...
          }
        }
      }
    }
  }

  // 3. 评估跨函数的影响

  // 检查是否传递给了外部函数
  for (Function *F : Result.calledFunctions)
  {
    if (F->isDeclaration())
    {
      Result.isPropagatedToExternalFunc = true;
      break;
    }
  }

  // 检查是否被热函数使用
  for (Function *F : Result.calledFunctions)
  {
    if (isHotFunction(F))
    {
      Result.isUsedInHotFunction = true;
      break;
    }
  }

  // 计算跨函数分数
  if (Result.calledFunctions.empty())
  {
    // 仅限本地使用
    Result.crossFuncScore = 5.0;
  }
  else if (Result.isPropagatedToExternalFunc)
  {
    // 传递给外部函数，增加不确定性
    Result.crossFuncScore = 2.0;
  }
  else if (Result.isUsedInHotFunction)
  {
    // 传递给热函数，可能更需要HBM
    Result.crossFuncScore = 15.0;
  }
  else
  {
    // 传递给其他内部函数
    Result.crossFuncScore = 8.0 + Result.calledFunctions.size() * 1.5;
  }

  return Result;
}

// 追踪指针传递到的函数
bool MyFunctionAnalysisPass::trackPointerToFunction(Value *Ptr, Function *F,
                                                    std::set<Function *> &VisitedFuncs,
                                                    std::vector<Function *> &TargetFuncs)
{
  if (!Ptr || !F || VisitedFuncs.count(F))
    return false;

  VisitedFuncs.insert(F);
  bool Found = false;

  // 追踪指针在函数内的使用
  for (auto &BB : *F)
  {
    for (auto &I : BB)
    {
      // 检查是否将指针作为参数传递给其他函数
      if (auto *Call = dyn_cast<CallInst>(&I))
      {
        Function *Callee = Call->getCalledFunction();
        if (!Callee)
          continue;

        // 检查每个参数
        for (unsigned i = 0; i < Call->arg_size(); ++i)
        {
          Value *Arg = Call->getArgOperand(i);

          // 如果参数是指针或其衍生（例如GEP结果）
          if (Arg == Ptr || isPtrDerivedFrom(Arg, Ptr))
          {
            TargetFuncs.push_back(Callee);
            Found = true;

            // 递归追踪到被调用函数
            if (!Callee->isDeclaration())
            {
              // 获取对应的形参
              if (i < Callee->arg_size())
              {
                Argument *FormalArg = Callee->getArg(i);
                trackPointerToFunction(FormalArg, Callee, VisitedFuncs, TargetFuncs);
              }
            }
          }
        }
      }
    }
  }

  return Found;
}

// 辅助函数：检查一个指针是否派生自另一个指针
bool MyFunctionAnalysisPass::isPtrDerivedFrom(Value *Derived, Value *Base)
{
  if (Derived == Base)
    return true;

  if (auto *GEP = dyn_cast<GetElementPtrInst>(Derived))
  {
    return isPtrDerivedFrom(GEP->getPointerOperand(), Base);
  }
  else if (auto *BC = dyn_cast<BitCastInst>(Derived))
  {
    return isPtrDerivedFrom(BC->getOperand(0), Base);
  }

  return false;
}

// 判断一个函数是否是热函数
bool MyFunctionAnalysisPass::isHotFunction(Function *F)
{
  if (!F)
    return false;

  // 检查函数属性
  if (F->hasFnAttribute("hot"))
    return true;

  // 检查函数名提示
  if (F->getName().contains("hot") ||
      F->getName().contains("main") ||
      F->getName().contains("kernel"))
    return true;

  // 检查Profile数据
  if (MDNode *ProfMD = F->getMetadata("prof.count"))
  {
    if (ProfMD->getNumOperands() > 0)
    {
      if (auto *CountMD = dyn_cast<ConstantAsMetadata>(ProfMD->getOperand(0)))
      {
        if (auto *Count = dyn_cast<ConstantInt>(CountMD->getValue()))
        {
          // 假设阈值为1000
          return Count->getZExtValue() > 1000;
        }
      }
    }
  }

  return false;
}

// 分析数据流
DataFlowInfo MyFunctionAnalysisPass::analyzeDataFlow(Value *AllocPtr, Function &F)
{
  DataFlowInfo Result;
  if (!AllocPtr)
    return Result;

  // 1. 找出数据流的所有使用点
  std::vector<Instruction *> UseInsts;
  std::set<BasicBlock *> UseBlocks;

  // 收集直接使用和衍生使用
  std::queue<Value *> WorkList;
  std::set<Value *> Visited;
  WorkList.push(AllocPtr);

  while (!WorkList.empty())
  {
    Value *V = WorkList.front();
    WorkList.pop();

    if (!Visited.insert(V).second)
      continue;

    for (User *U : V->users())
    {
      if (auto *I = dyn_cast<Instruction>(U))
      {
        if (I->getFunction() == &F)
        {
          UseInsts.push_back(I);
          UseBlocks.insert(I->getParent());

          // 继续跟踪衍生值
          if (isa<GetElementPtrInst>(I) || isa<BitCastInst>(I) ||
              isa<LoadInst>(I) || isa<PHINode>(I) || isa<SelectInst>(I))
          {
            WorkList.push(I);
          }
        }
      }
    }
  }

  // 2. 找出可能的阶段转换点 (phase transition points)
  std::set<BasicBlock *> TransitionBlocks = findPhaseTransitionPoints(AllocPtr, F);

  // 3. 基于使用模式推断生命周期阶段
  // 假设分配指令为 ALLOCATION 阶段
  if (auto *AllocInst = dyn_cast<Instruction>(AllocPtr))
  {
    Result.phaseMap[AllocInst] = DataFlowInfo::LifetimePhase::ALLOCATION;
  }

  // 找出初始化阶段（分配后的写入）
  bool foundInit = false;
  for (Instruction *I : UseInsts)
  {
    if (auto *SI = dyn_cast<StoreInst>(I))
    {
      // 判断是否是对分配内存的写入
      if (isPtrDerivedFrom(SI->getPointerOperand(), AllocPtr))
      {
        // 检查该存储是否靠近分配点
        if (isInstructionNear(SI, AllocPtr, 20))
        {
          Result.phaseMap[SI] = DataFlowInfo::LifetimePhase::INITIALIZATION;
          foundInit = true;
        }
      }
    }

    // 处理memset/memcpy等初始化函数
    if (auto *Call = dyn_cast<CallInst>(I))
    {
      Function *Callee = Call->getCalledFunction();
      if (Callee)
      {
        StringRef Name = Callee->getName();
        if (Name.contains("memset") || Name.contains("memcpy") || Name.contains("memmove"))
        {
          if (isPtrDerivedFrom(Call->getArgOperand(0), AllocPtr))
          {
            Result.phaseMap[Call] = DataFlowInfo::LifetimePhase::INITIALIZATION;
            foundInit = true;
          }
        }
      }
    }
  }
  Result.hasInitPhase = foundInit;

  // 识别活跃使用阶段 (ACTIVE_USE)
  unsigned activeUseCount = 0;
  for (Instruction *I : UseInsts)
  {
    // 如果已经分类，则跳过
    if (Result.phaseMap.count(I))
      continue;

    if (auto *LI = dyn_cast<LoadInst>(I))
    {
      if (isPtrDerivedFrom(LI->getPointerOperand(), AllocPtr))
      {
        Result.phaseMap[LI] = DataFlowInfo::LifetimePhase::ACTIVE_USE;
        activeUseCount++;
      }
    }
    else if (auto *SI = dyn_cast<StoreInst>(I))
    {
      if (isPtrDerivedFrom(SI->getPointerOperand(), AllocPtr))
      {
        // 初始化后的写入视为活跃使用
        if (!isInstructionNear(SI, AllocPtr, 20))
        {
          Result.phaseMap[SI] = DataFlowInfo::LifetimePhase::ACTIVE_USE;
          activeUseCount++;
        }
      }
    }
    else if (auto *Call = dyn_cast<CallInst>(I))
    {
      // 指针作为参数传递给函数调用
      for (unsigned i = 0; i < Call->arg_size(); ++i)
      {
        if (isPtrDerivedFrom(Call->getArgOperand(i), AllocPtr))
        {
          Result.phaseMap[Call] = DataFlowInfo::LifetimePhase::ACTIVE_USE;
          activeUseCount++;
          break;
        }
      }
    }
  }

  // 识别只读阶段 (READ_ONLY)
  // 假设分配的内存在某个点之后只被读取不被写入
  bool enteredReadOnly = false;
  for (BasicBlock *BB : TransitionBlocks)
  {
    // 检查该基本块后的所有使用是否只是读取
    bool onlyReads = true;
    for (Instruction *I : UseInsts)
    {
      if (dominates(BB, I->getParent()))
      {
        if (auto *SI = dyn_cast<StoreInst>(I))
        {
          if (isPtrDerivedFrom(SI->getPointerOperand(), AllocPtr))
          {
            onlyReads = false;
            break;
          }
        }
      }
    }

    if (onlyReads)
    {
      enteredReadOnly = true;
      // 标记该基本块后的所有读取为只读阶段
      for (Instruction *I : UseInsts)
      {
        if (dominates(BB, I->getParent()))
        {
          if (auto *LI = dyn_cast<LoadInst>(I))
          {
            if (isPtrDerivedFrom(LI->getPointerOperand(), AllocPtr))
            {
              Result.phaseMap[LI] = DataFlowInfo::LifetimePhase::READ_ONLY;
            }
          }
        }
      }
    }
  }
  Result.hasReadOnlyPhase = enteredReadOnly;

  // 识别释放阶段 (DEALLOCATION)
  for (Instruction *I : UseInsts)
  {
    if (auto *Call = dyn_cast<CallInst>(I))
    {
      Function *Callee = Call->getCalledFunction();
      if (Callee)
      {
        StringRef Name = Callee->getName();
        if (Name == "free" || Name.startswith("_Zd"))
        {
          if (Call->arg_size() >= 1 &&
              isPtrDerivedFrom(Call->getArgOperand(0), AllocPtr))
          {
            Result.phaseMap[Call] = DataFlowInfo::LifetimePhase::DEALLOCATION;
          }
        }
      }
    }
  }

  // 识别休眠阶段 (DORMANT)
  // 如果指针在某段时间没有被访问
  std::set<BasicBlock *> DormantCandidates;
  for (BasicBlock &BB : F)
  {
    // 如果基本块不包含指针的任何使用
    if (UseBlocks.count(&BB) == 0)
    {
      // 并且基本块被执行的路径上离使用点有一定距离
      bool isPotentialDormant = true;
      for (BasicBlock *UB : UseBlocks)
      {
        if (isPotentiallyReachableFromTo(&BB, UB, nullptr, nullptr, true))
        {
          if (getApproximateBlockDistance(&BB, UB) < 5)
          {
            isPotentialDormant = false;
            break;
          }
        }
      }

      if (isPotentialDormant)
      {
        DormantCandidates.insert(&BB);
      }
    }
  }

  Result.hasDormantPhase = !DormantCandidates.empty();

  // 计算每个阶段的平均使用次数
  std::map<DataFlowInfo::LifetimePhase, unsigned> PhaseUseCounts;
  for (auto &Pair : Result.phaseMap)
  {
    PhaseUseCounts[Pair.second]++;
  }

  unsigned totalPhases = 0;
  unsigned totalUses = 0;
  for (auto &Pair : PhaseUseCounts)
  {
    if (Pair.first != DataFlowInfo::LifetimePhase::ALLOCATION &&
        Pair.first != DataFlowInfo::LifetimePhase::DEALLOCATION)
    {
      totalPhases++;
      totalUses += Pair.second;
    }
  }

  Result.avgUsesPerPhase = totalPhases > 0 ? double(totalUses) / totalPhases : 0.0;

  // 计算数据流分数
  Result.dataFlowScore = 0.0;

  // 有初始化阶段和活跃使用的数据更可能是热点
  if (Result.hasInitPhase && activeUseCount > 0)
  {
    Result.dataFlowScore += 10.0;
  }

  // 有只读阶段的数据可能适合一次性加载到HBM
  if (Result.hasReadOnlyPhase)
  {
    Result.dataFlowScore += 15.0;
  }

  // 没有休眠阶段的数据可能更活跃
  if (!Result.hasDormantPhase)
  {
    Result.dataFlowScore += 5.0;
  }

  // 根据使用密度调整分数
  Result.dataFlowScore += std::min(20.0, Result.avgUsesPerPhase * 2.0);

  return Result;
}

// 找出可能的阶段转换点
std::set<BasicBlock *> MyFunctionAnalysisPass::findPhaseTransitionPoints(Value *Ptr, Function &F)
{
  std::set<BasicBlock *> Result;

  // 找出循环出口点
  LoopInfo LI{DominatorTree(F)};
  for (auto &L : LI)
  {
    SmallVector<BasicBlock *, 4> ExitBlocks;
    L->getExitBlocks(ExitBlocks);
    for (BasicBlock *ExitBB : ExitBlocks)
    {
      Result.insert(ExitBB);
    }
  }

  // 找出包含条件分支的基本块
  for (auto &BB : F)
  {
    if (auto *BI = dyn_cast<BranchInst>(BB.getTerminator()))
    {
      if (BI->isConditional())
      {
        // 检查条件是否与指针相关
        Value *Cond = BI->getCondition();
        if (isPtrValueDependent(Cond, Ptr))
        {
          Result.insert(&BB);
        }
      }
    }
  }

  return Result;
}

// 辅助函数：判断一个条件是否依赖于指针
bool MyFunctionAnalysisPass::isPtrValueDependent(Value *Cond, Value *Ptr)
{
  if (!Cond || !Ptr)
    return false;

  std::set<Value *> Visited;
  std::queue<Value *> WorkList;
  WorkList.push(Cond);

  while (!WorkList.empty())
  {
    Value *V = WorkList.front();
    WorkList.pop();

    if (!Visited.insert(V).second)
      continue;

    if (auto *LI = dyn_cast<LoadInst>(V))
    {
      if (isPtrDerivedFrom(LI->getPointerOperand(), Ptr))
      {
        return true;
      }
    }

    if (auto *I = dyn_cast<Instruction>(V))
    {
      for (Use &U : I->operands())
      {
        WorkList.push(U.get());
      }
    }
  }

  return false;
}

// 辅助函数：判断两个指令是否相近
bool MyFunctionAnalysisPass::isInstructionNear(Instruction *I1, Value *I2, unsigned threshold)
{
  if (auto *I2Inst = dyn_cast<Instruction>(I2))
  {
    if (I1->getParent() == I2Inst->getParent())
    {
      // 如果在同一基本块，检查指令间距
      BasicBlock *BB = I1->getParent();
      unsigned distance = 0;
      bool foundFirst = false;

      for (auto &I : *BB)
      {
        if (&I == I1 || &I == I2Inst)
        {
          if (!foundFirst)
          {
            foundFirst = true;
          }
          else
          {
            return distance < threshold;
          }
        }

        if (foundFirst)
        {
          distance++;
        }
      }
    }
  }

  return false;
}

// 辅助函数：计算两个基本块的近似距离
unsigned MyFunctionAnalysisPass::getApproximateBlockDistance(BasicBlock *BB1, BasicBlock *BB2)
{
  if (BB1 == BB2)
    return 0;

  std::set<BasicBlock *> Visited;
  std::queue<std::pair<BasicBlock *, unsigned>> WorkList;
  WorkList.push({BB1, 0});

  while (!WorkList.empty())
  {
    auto [BB, distance] = WorkList.front();
    WorkList.pop();

    if (!Visited.insert(BB).second)
      continue;

    if (BB == BB2)
      return distance;

    for (auto *Succ : successors(BB))
    {
      WorkList.push({Succ, distance + 1});
    }
  }

  return UINT_MAX; // 无法到达
}

// 分析竞争
ContentionInfo MyFunctionAnalysisPass::analyzeContention(Value *AllocPtr, Function &F)
{
  ContentionInfo Result;
  if (!AllocPtr)
    return Result;

  // 检查是否为并行函数
  bool isParallelFunction = detectParallelRuntime(F);
  if (!isParallelFunction)
  {
    // 非并行函数不存在竞争
    return Result;
  }

  // 收集所有对该指针的使用
  std::vector<Instruction *> UseInsts;
  std::queue<Value *> WorkList;
  std::set<Value *> Visited;
  WorkList.push(AllocPtr);

  while (!WorkList.empty())
  {
    Value *V = WorkList.front();
    WorkList.pop();

    if (!Visited.insert(V).second)
      continue;

    for (User *U : V->users())
    {
      if (auto *I = dyn_cast<Instruction>(U))
      {
        if (I->getFunction() == &F)
        {
          UseInsts.push_back(I);

          // 继续跟踪衍生值
          if (isa<GetElementPtrInst>(I) || isa<BitCastInst>(I) ||
              isa<LoadInst>(I) || isa<PHINode>(I) || isa<SelectInst>(I))
          {
            WorkList.push(I);
          }
        }
      }
    }
  }

  // 没有使用，无竞争
  if (UseInsts.empty())
  {
    return Result;
  }

  // 估计线程数
  unsigned threadCount = estimateParallelThreads(F);

  // 1. 检查伪共享
  bool hasFalseSharing = false;
  DataLayout DL = F.getParent()->getDataLayout();

  // 找出所有GEP指令
  for (Instruction *I : UseInsts)
  {
    if (auto *GEP = dyn_cast<GetElementPtrInst>(I))
    {
      // 检查元素大小
      Type *ElemTy = GEP->getResultElementType();
      unsigned elemSize = DL.getTypeAllocSize(ElemTy);

      if (detectFalseSharing(GEP, elemSize, threadCount))
      {
        hasFalseSharing = true;
        Result.potentialContentionPoints++;
      }
    }
  }

  // 2. 检查原子操作竞争
  bool hasAtomicContention = false;
  for (Instruction *I : UseInsts)
  {
    if (isa<AtomicRMWInst>(I) || isa<AtomicCmpXchgInst>(I) ||
        (isa<LoadInst>(I) && cast<LoadInst>(I)->isAtomic()) ||
        (isa<StoreInst>(I) && cast<StoreInst>(I)->isAtomic()))
    {
      hasAtomicContention = true;
      Result.potentialContentionPoints++;
    }
  }

  // 3. 检查锁竞争
  bool hasLockContention = false;
  for (Instruction *I : UseInsts)
  {
    if (auto *Call = dyn_cast<CallInst>(I))
    {
      Function *Callee = Call->getCalledFunction();
      if (Callee)
      {
        StringRef Name = Callee->getName();
        if (Name.contains("lock") || Name.contains("mutex") ||
            Name.contains("critical") || Name.contains("barrier"))
        {
          hasLockContention = true;
          Result.potentialContentionPoints++;
        }
      }
    }
  }

  // 4. 检查带宽竞争
  bool hasBandwidthContention = false;
  LoopInfo LI{DominatorTree(F)};
  for (auto &L : LI)
  {
    if (detectBandwidthContention(AllocPtr, L, threadCount))
    {
      hasBandwidthContention = true;
      Result.potentialContentionPoints++;
    }
  }

  // 确定竞争类型和概率
  if (hasBandwidthContention)
  {
    Result.type = ContentionInfo::ContentionType::BANDWIDTH_CONTENTION;
    Result.contentionProbability = 0.8; // 带宽竞争概率很高
  }
  else if (hasLockContention)
  {
    Result.type = ContentionInfo::ContentionType::LOCK_CONTENTION;
    Result.contentionProbability = 0.6; // 锁竞争概率中等
  }
  else if (hasAtomicContention)
  {
    Result.type = ContentionInfo::ContentionType::ATOMIC_CONTENTION;
    Result.contentionProbability = 0.7; // 原子操作竞争概率较高
  }
  else if (hasFalseSharing)
  {
    Result.type = ContentionInfo::ContentionType::FALSE_SHARING;
    Result.contentionProbability = 0.5; // 伪共享概率一般
  }
  else
  {
    Result.type = ContentionInfo::ContentionType::NONE;
    Result.contentionProbability = 0.0;
  }

  // 计算竞争分数
  // 带宽竞争对HBM需求更高，其他竞争则降低HBM的效益
  if (Result.type == ContentionInfo::ContentionType::BANDWIDTH_CONTENTION)
  {
    // 带宽竞争是HBM的主要目标
    Result.contentionScore = 25.0 * Result.contentionProbability;
  }
  else if (Result.type == ContentionInfo::ContentionType::FALSE_SHARING)
  {
    // 伪共享对HBM带宽的利用不太好
    Result.contentionScore = -10.0 * Result.contentionProbability;
  }
  else if (Result.type == ContentionInfo::ContentionType::ATOMIC_CONTENTION)
  {
    // 原子操作竞争会降低并行效率
    Result.contentionScore = -15.0 * Result.contentionProbability;
  }
  else if (Result.type == ContentionInfo::ContentionType::LOCK_CONTENTION)
  {
    // 锁竞争会严重降低并行效率
    Result.contentionScore = -20.0 * Result.contentionProbability;
  }

  // 调整基于竞争点数量的分数
  if (Result.potentialContentionPoints > 1)
  {
    // 多个竞争点会放大效应
    Result.contentionScore *= (1.0 + 0.1 * std::min(10u, Result.potentialContentionPoints));
  }

  return Result;
}

// 检测伪共享
bool MyFunctionAnalysisPass::detectFalseSharing(Value *Ptr, unsigned elemSize, unsigned threadCount)
{
  if (!Ptr || elemSize == 0 || threadCount <= 1)
    return false;

  // 如果元素大小小于缓存行大小的一部分，可能存在伪共享
  const unsigned CacheLineSize = 64; // 典型的缓存行大小

  if (elemSize < CacheLineSize / 4)
  {
    // 检查索引是否与线程ID相关
    if (auto *GEP = dyn_cast<GetElementPtrInst>(Ptr))
    {
      for (auto I = GEP->idx_begin(), E = GEP->idx_end(); I != E; ++I)
      {
        Value *Idx = *I;

        // 检查索引是否依赖线程ID
        if (isThreadIDRelated(Idx))
        {
          // 如果索引与线程ID相关，且元素很小，可能导致伪共享
          return true;
        }
      }
    }
  }

  return false;
}

// 检测带宽竞争
bool MyFunctionAnalysisPass::detectBandwidthContention(Value *Ptr, Loop *L, unsigned threadCount)
{
  if (!Ptr || !L || threadCount <= 1)
    return false;

  // 1. 检查循环是否是并行循环
  Instruction *Term = L->getHeader()->getTerminator();
  bool isParallelLoop = Term && Term->getMetadata("llvm.loop.parallel_accesses");

  if (!isParallelLoop)
  {
    // 检查是否有其他并行提示
    for (BasicBlock *BB : L->getBlocks())
    {
      for (Instruction &I : *BB)
      {
        if (auto *Call = dyn_cast<CallInst>(&I))
        {
          Function *Callee = Call->getCalledFunction();
          if (Callee && (Callee->getName().contains("parallel") ||
                         Callee->getName().contains("omp") ||
                         Callee->getName().contains("thread")))
          {
            isParallelLoop = true;
            break;
          }
        }

        if (isParallelLoop)
          break;
      }
    }
  }

  if (!isParallelLoop)
    return false;

  // 2. 检查是否有频繁的内存访问
  unsigned memOpCount = 0;
  bool usesPtr = false;

  for (BasicBlock *BB : L->getBlocks())
  {
    for (Instruction &I : *BB)
    {
      if (auto *LI = dyn_cast<LoadInst>(&I))
      {
        memOpCount++;
        if (isPtrDerivedFrom(LI->getPointerOperand(), Ptr))
        {
          usesPtr = true;
        }
      }
      else if (auto *SI = dyn_cast<StoreInst>(&I))
      {
        memOpCount++;
        if (isPtrDerivedFrom(SI->getPointerOperand(), Ptr))
        {
          usesPtr = true;
        }
      }
    }
  }

  // 如果循环中没有使用该指针，则不存在带宽竞争
  if (!usesPtr)
    return false;

  // 3. 估计循环迭代次数
  unsigned tripCount = getLoopTripCount(L, *SE);

  // 4. 估计带宽使用
  // 假设每个存储器操作平均访问 8 字节
  uint64_t bytesPerIteration = memOpCount * 8;
  uint64_t totalBytes = bytesPerIteration * tripCount;

  // 5. 考虑线程数的影响
  // 多线程会放大带宽需求
  uint64_t estimatedBandwidth = totalBytes * threadCount;

  // 如果预计带宽使用超过阈值，认为存在带宽竞争
  const uint64_t BandwidthThreshold = 1ULL * 1024 * 1024 * 1024; // 1 GB

  return estimatedBandwidth > BandwidthThreshold;
}

// 添加这些实现到 MyFunctionAnalysisPass.cpp 文件末尾

// 添加 dominates 函数实现
bool MyFunctionAnalysisPass::dominates(BasicBlock *A, BasicBlock *B)
{
  if (A == B)
    return true;
  llvm::DominatorTree DT(*A->getParent());
  return DT.dominates(A, B);
}

// 添加 isPotentiallyReachableFromTo 函数实现
bool MyFunctionAnalysisPass::isPotentiallyReachableFromTo(BasicBlock *From, BasicBlock *To,
                                                          void *domTree, void *postDomTree, bool exact)
{
  if (From == To)
    return true;

  // 简单实现：检查是否有路径从From到To
  std::set<BasicBlock *> Visited;
  std::queue<BasicBlock *> WorkList;
  WorkList.push(From);

  while (!WorkList.empty())
  {
    BasicBlock *BB = WorkList.front();
    WorkList.pop();

    if (!Visited.insert(BB).second)
      continue;

    if (BB == To)
      return true;

    for (auto *Succ : successors(BB))
    {
      WorkList.push(Succ);
    }
  }

  return false;
}

// 添加 isPointerAccessedByCall 函数实现
bool MyFunctionAnalysisPass::isPointerAccessedByCall(CallInst *Call, Value *Ptr, AAResults &AA)
{
  if (!Call || !Ptr)
    return false;

  // 遍历所有参数
  for (unsigned i = 0; i < Call->arg_size(); ++i)
  {
    Value *Arg = Call->getArgOperand(i);
    if (!Arg->getType()->isPointerTy())
      continue;

    // 检查参数是否可能指向与Ptr相同的内存
    AliasResult AR = AA.alias(Arg, Ptr);
    if (AR != AliasResult::NoAlias)
      return true;
  }

  return false;
}

// 添加 isThreadLocalStorage 函数实现
bool MyFunctionAnalysisPass::isThreadLocalStorage(Value *Ptr)
{
  if (!Ptr)
    return false;

  // 检查是否为线程本地变量
  if (auto *GV = dyn_cast<GlobalVariable>(Ptr))
    return GV->isThreadLocal();

  // 检查是否为局部变量（栈上分配，通常是线程本地的）
  if (isa<AllocaInst>(Ptr))
    return true;

  // 检查是否显式标记为线程本地
  if (auto *I = dyn_cast<Instruction>(Ptr))
  {
    if (I->getMetadata("thread_local"))
      return true;
  }

  return false;
}

// 添加 isPtrValueDependent 函数实现
bool MyFunctionAnalysisPass::isPtrValueDependent(Value *Cond, Value *Ptr)
{
  if (!Cond || !Ptr)
    return false;

  std::set<Value *> Visited;
  std::queue<Value *> WorkList;
  WorkList.push(Cond);

  while (!WorkList.empty())
  {
    Value *V = WorkList.front();
    WorkList.pop();

    if (!Visited.insert(V).second)
      continue;

    if (auto *LI = dyn_cast<LoadInst>(V))
    {
      if (isPtrDerivedFrom(LI->getPointerOperand(), Ptr))
      {
        return true;
      }
    }

    if (auto *I = dyn_cast<Instruction>(V))
    {
      for (Use &U : I->operands())
      {
        WorkList.push(U.get());
      }
    }
  }

  return false;
}

// 添加 isPtrDerivedFrom 函数实现（如果不存在）
bool MyFunctionAnalysisPass::isPtrDerivedFrom(Value *Derived, Value *Base)
{
  if (Derived == Base)
    return true;

  if (auto *GEP = dyn_cast<GetElementPtrInst>(Derived))
  {
    return isPtrDerivedFrom(GEP->getPointerOperand(), Base);
  }
  else if (auto *BC = dyn_cast<BitCastInst>(Derived))
  {
    return isPtrDerivedFrom(BC->getOperand(0), Base);
  }

  return false;
}

// 添加 isInstructionNear 函数实现
bool MyFunctionAnalysisPass::isInstructionNear(Instruction *I1, Value *I2, unsigned threshold)
{
  if (auto *I2Inst = dyn_cast<Instruction>(I2))
  {
    if (I1->getParent() == I2Inst->getParent())
    {
      // 如果在同一基本块，检查指令间距
      BasicBlock *BB = I1->getParent();
      unsigned distance = 0;
      bool foundFirst = false;

      for (auto &I : *BB)
      {
        if (&I == I1 || &I == I2Inst)
        {
          if (!foundFirst)
          {
            foundFirst = true;
          }
          else
          {
            return distance < threshold;
          }
        }

        if (foundFirst)
        {
          distance++;
        }
      }
    }
  }

  return false;
}

// 添加 getApproximateBlockDistance 函数实现
unsigned MyFunctionAnalysisPass::getApproximateBlockDistance(BasicBlock *BB1, BasicBlock *BB2)
{
  if (BB1 == BB2)
    return 0;

  std::set<BasicBlock *> Visited;
  std::queue<std::pair<BasicBlock *, unsigned>> WorkList;
  WorkList.push({BB1, 0});

  while (!WorkList.empty())
  {
    auto [BB, distance] = WorkList.front();
    WorkList.pop();

    if (!Visited.insert(BB).second)
      continue;

    if (BB == BB2)
      return distance;

    for (auto *Succ : successors(BB))
    {
      WorkList.push({Succ, distance + 1});
    }
  }

  return UINT_MAX; // 无法到达
}

// 添加 isMayLoadFromMemory 函数实现（如果不存在）
bool MyFunctionAnalysisPass::isMayLoadFromMemory(Value *V)
{
  if (!V)
    return false;

  if (isa<LoadInst>(V))
    return true;
  if (isa<CallInst>(V) || isa<InvokeInst>(V))
    return true;

  if (auto *I = dyn_cast<Instruction>(V))
  {
    for (Use &U : I->operands())
    {
      if (isMayLoadFromMemory(U.get()))
        return true;
    }
  }

  return false;
}

Value *MyFunctionAnalysisPass::resolveBasePointer(Value *V)
{
  // 使用 SmallPtrSet 进行访问记录，这比 std::set 更高效
  SmallPtrSet<Value *, 16> Visited;
  // 使用 SmallVector 作为工作列表，适合这种短期存储的场景
  SmallVector<Value *, 8> Worklist;

  Worklist.push_back(V);

  while (!Worklist.empty())
  {
    Value *Cur = Worklist.pop_back_val();

    // 如果已访问过，跳过
    if (!Visited.insert(Cur).second)
      continue;

    // 检查是否为分配函数调用
    if (auto *CI = dyn_cast<CallInst>(Cur))
    {
      Function *Callee = CI->getCalledFunction();
      // 检查直接调用
      if (Callee)
      {
        StringRef Name = Callee->getName();
        // 检查各种常见的内存分配函数
        if (Name == "malloc" ||
            Name == "calloc" ||
            Name == "realloc" ||
            Name.startswith("_Znwm") || // C++ new
            Name.startswith("_Znam") || // C++ new[]
            Name.contains("alloc"))     // 其他可能的分配函数
          return CI;
      }
      // 无法解析的调用，可能是间接调用
      else if (CI->isIndirectCall())
      {
        // 尝试通过类型启发式判断是否为分配函数
        Type *RetTy = CI->getType();
        if (RetTy->isPointerTy() && CI->arg_size() > 0)
        {
          // 第一个参数通常是大小
          Value *FirstArg = CI->getArgOperand(0);
          if (FirstArg->getType()->isIntegerTy())
            return CI; // 可能是分配函数
        }
      }
    }

    // 处理各种指针操作指令
    if (auto *GEP = dyn_cast<GetElementPtrInst>(Cur))
      Worklist.push_back(GEP->getPointerOperand());
    else if (auto *BC = dyn_cast<BitCastOperator>(Cur))
      Worklist.push_back(BC->getOperand(0));
    else if (auto *ASCI = dyn_cast<AddrSpaceCastInst>(Cur))
      Worklist.push_back(ASCI->getPointerOperand());
    else if (auto *PN = dyn_cast<PHINode>(Cur))
    {
      for (Value *Incoming : PN->incoming_values())
        Worklist.push_back(Incoming);
    }
    else if (auto *SI = dyn_cast<SelectInst>(Cur))
    {
      Worklist.push_back(SI->getTrueValue());
      Worklist.push_back(SI->getFalseValue());
    }
    else if (auto *LI = dyn_cast<LoadInst>(Cur))
      Worklist.push_back(LI->getPointerOperand());
    else if (auto *Gep = dyn_cast<GEPOperator>(Cur))
      Worklist.push_back(Gep->getPointerOperand());
    else if (auto *BC = dyn_cast<BitCastInst>(Cur))
      Worklist.push_back(BC->getOperand(0));
  }

  // 无法找到基地址
  return nullptr;
}