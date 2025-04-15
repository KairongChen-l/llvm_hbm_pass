#ifndef MY_FUNCTION_ANALYSIS_PASS_H
#define MY_FUNCTION_ANALYSIS_PASS_H

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/MemorySSA.h"
#include "llvm/Analysis/LoopAccessAnalysis.h"
#include "llvm/Analysis/DominatorTree.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/CommandLine.h"
#include <set>
#include <unordered_set>
#include <queue>
#include <optional>
#include <vector>
#include <string>
#include <map>

namespace MyAdvancedHBM {

// 枚举定义步长类型
enum class StrideType {
  UNKNOWN,    // 无法确定
  IRREGULAR,  // 不规则访问
  COMPLEX,    // 复杂但有规律的访问
  LINEAR,     // 线性步长访问
  CONSTANT    // 常量步长访问（最优）
};

// Profile引导优化
struct ProfileGuidedInfo {
  bool hasProfileData = false;
  double staticConfidence = 0.0;  // 0.0-1.0，表示对静态分析结果的信心
  double dynamicWeight = 0.0;     // 动态Profile的权重
  std::vector<std::pair<std::string, double>> hotspotHints; // 热点提示
};

// 自适应阈值分析
struct AdaptiveThresholdInfo {
  double baseThreshold = 50.0;   // 基础阈值
  double adjustedThreshold = 50.0; // 调整后的阈值
  std::string adjustmentReason;    // 调整原因
};

// 多维度评分
struct MultiDimensionalScore {
  double bandwidthScore = 0.0;   // 带宽需求得分
  double latencyScore = 0.0;     // 延迟敏感度得分
  double utilizationScore = 0.0;  // 利用率得分
  double sizeEfficiencyScore = 0.0; // 大小效率得分
  double finalScore = 0.0;       // 最终综合得分
};

// 跨函数分析
struct CrossFunctionInfo {
  bool analyzedCrossFn = false;
  std::vector<llvm::Function*> calledFunctions;
  std::vector<llvm::Function*> callerFunctions;
  bool isPropagatedToExternalFunc = false;
  bool isUsedInHotFunction = false;
  double crossFuncScore = 0.0;
};

// 全程序数据流分析
struct DataFlowInfo {
  enum class LifetimePhase {
    ALLOCATION,
    INITIALIZATION,
    ACTIVE_USE,
    READ_ONLY,
    DORMANT,
    DEALLOCATION
  };
  
  std::map<llvm::Instruction*, LifetimePhase> phaseMap;
  bool hasInitPhase = false;
  bool hasReadOnlyPhase = false;
  bool hasDormantPhase = false;
  double avgUsesPerPhase = 0.0;
  double dataFlowScore = 0.0;
};

// 竞争分析
struct ContentionInfo {
  enum class ContentionType {
    NONE,               // 无竞争
    FALSE_SHARING,      // 伪共享
    ATOMIC_CONTENTION,  // 原子操作竞争
    LOCK_CONTENTION,    // 锁竞争
    BANDWIDTH_CONTENTION // 带宽竞争
  };
  
  ContentionType type = ContentionType::NONE;
  double contentionProbability = 0.0;
  unsigned potentialContentionPoints = 0;
  double contentionScore = 0.0;
};

// 用于记录单个 malloc 调用点的分析结果
struct MallocRecord {
  llvm::CallInst *MallocCall = nullptr;
  std::vector<llvm::CallInst *> FreeCalls;

  // 位置信息（文件+行号）
  std::string SourceLocation;

  // 静态信息
  size_t AllocSize = 0;
  unsigned LoopDepth = 0;
  uint64_t TripCount = 1;

  // 状态标志（已有）
  bool IsParallel = false;
  bool IsVectorized = false;
  bool IsStreamAccess = false;
  bool IsThreadPartitioned = false;
  bool MayConflict = false;
  bool UserForcedHot = false;
  bool UnmatchedFree = false;

  // 动态 profile
  uint64_t DynamicAccessCount = 0;
  double EstimatedBandwidth = 0.0;

  // 为带宽计算添加的辅助字段
  uint64_t AccessedBytes = 0; // 添加这一行，分析访问的总字节数
  double AccessTime = 0.0;    // 添加这一行，访问所用的估计时间
  double BandwidthScore = 0.0; // 添加这一行，计算的带宽得分

  // 动态静态冲突标记
  bool WasDynamicHotButStaticLow = false;
  bool WasStaticHotButDynamicCold = false;

  // 增加并行访问分析字段
  std::string ParallelFramework;  // 并行框架类型（OpenMP、CUDA、TBB等）
  unsigned EstimatedThreads = 1;  // 估计的并行线程数
  bool HasAtomicAccess = false;   // 是否有原子访问
  bool HasFalseSharing = false;   // 是否存在伪共享
  bool IsReadOnly = false;        // 是否只读访问
  
  // 评分结果（原始总分）
  double Score = 0.0;

  // ====== 以下为拆分后的细化得分因子 ======

  // 加分项
  double StreamScore = 0.0;
  double VectorScore = 0.0;
  double ParallelScore = 0.0;

  // 扣分项
  double SSAPenalty = 0.0;
  double ChaosPenalty = 0.0;
  double ConflictPenalty = 0.0;

  // 新增的动态特性成员
  ProfileGuidedInfo ProfileInfo;
  double ProfileAdjustedScore = 0.0;
  
  // 多维度评分
  MultiDimensionalScore MultiDimScore;

  // 新增的扩展分析成员
  CrossFunctionInfo CrossFnInfo;
  DataFlowInfo DataFlowInfo;
  ContentionInfo ContentionInfo;
  
  // JSON输出辅助
  std::string ToJsonString() const; // 可选扩展
};

// 函数级的分析结果
struct FunctionMallocInfo {
  std::vector<MallocRecord> MallocRecords;
};

class MyFunctionAnalysisPass : public llvm::AnalysisInfoMixin<MyFunctionAnalysisPass> {
public:
  using Result = FunctionMallocInfo;
  Result run(llvm::Function &F, llvm::FunctionAnalysisManager &FAM);
  uint64_t getConstantAllocSize(llvm::Value *V);
  // 添加线程并行分析枚举
  enum class ThreadAccessPattern {
        UNKNOWN,           // 未知模式
        PRIVATE,           // 线程私有数据
        PARTITIONED,       // 按线程ID分区访问（良性）
        SHARED_READONLY,   // 只读共享（良性）
        SHARED_WRITE,      // 写入共享（可能有冲突）
        ATOMIC_ACCESS,     // 原子访问（有同步开销）
        FALSE_SHARING      // 伪共享（不良）
    };
  
  // 数据局部性分析
  enum class LocalityType {
    POOR,       // 差的局部性
    MODERATE,   // 中等局部性
    GOOD,       // 良好的局部性
    EXCELLENT   // 极佳的局部性
  };
  LocalityType analyzeDataLocality(llvm::Value *Ptr, llvm::Loop *L, llvm::ScalarEvolution &SE);
  
  // 交错访问模式分析
  struct InterleavedAccessInfo {
    bool isInterleaved = false;
    unsigned accessedArrays = 0;
    double strideRatio = 0.0;
    bool isPotentiallyBandwidthBound = false;
  };
  InterleavedAccessInfo analyzeInterleavedAccess(llvm::Loop *L, llvm::ScalarEvolution &SE);

  ProfileGuidedInfo analyzeProfileData(llvm::CallInst *MallocCall, llvm::Function &F);
  double adjustScoreWithProfile(double staticScore, const ProfileGuidedInfo &PGI);
  
  AdaptiveThresholdInfo computeAdaptiveThreshold(llvm::Module &M, const std::vector<MallocRecord> &AllMallocs);
  
  MultiDimensionalScore computeMultiDimensionalScore(const MallocRecord &MR);
  
  CrossFunctionInfo analyzeCrossFunctionUsage(llvm::Value *AllocPtr, llvm::Module &M);
  bool trackPointerToFunction(llvm::Value *Ptr, llvm::Function *F, 
                            std::set<llvm::Function*> &VisitedFuncs,
                            std::vector<llvm::Function*> &TargetFuncs);
  bool isHotFunction(llvm::Function *F);

  DataFlowInfo analyzeDataFlow(llvm::Value *AllocPtr, llvm::Function &F);
  std::set<llvm::BasicBlock*> findPhaseTransitionPoints(llvm::Value *Ptr, llvm::Function &F);

  ContentionInfo analyzeContention(llvm::Value *AllocPtr, llvm::Function &F);
  bool detectFalseSharing(llvm::Value *Ptr, unsigned elemSize, unsigned threadCount);
  bool detectBandwidthContention(llvm::Value *Ptr, llvm::Loop *L, unsigned threadCount);
  
  // 添加新的线程并行分析函数
  ThreadAccessPattern analyzeThreadAccess(llvm::Value *Ptr, llvm::Instruction *I);
  bool isOpenMPParallel(llvm::Function &F);
  bool isCUDAParallel(llvm::Function &F);
  bool isTBBParallel(llvm::Function &F);
  unsigned estimateParallelThreads(llvm::Function &F);
  bool isAtomicAccess(llvm::Instruction *I);
  bool hasParallelLoopMetadata(llvm::Loop *L);
  bool detectFalseSharing(llvm::Value *Ptr, llvm::DataLayout &DL);
  bool isThreadDependentAccess(llvm::Value *Ptr);
  bool isThreadSafeAccess(llvm::Value *Ptr, llvm::AAResults &AA);
  
  friend llvm::AnalysisInfoMixin<MyFunctionAnalysisPass>;
  static llvm::AnalysisKey Key;

  // 新增辅助函数声明
  bool isMayLoadFromMemory(llvm::Value *V);
  bool isPointerAccessedByCall(llvm::CallInst *Call, llvm::Value *Ptr, llvm::AAResults &AA);
  bool isThreadLocalStorage(llvm::Value *Ptr);
  bool isPtrValueDependent(llvm::Value *Cond, llvm::Value *Ptr);
  bool dominates(llvm::BasicBlock *A, llvm::BasicBlock *B);
  bool isPotentiallyReachableFromTo(llvm::BasicBlock *From, llvm::BasicBlock *To, 
                                   void* domTree, void* postDomTree, bool exact);
  bool isPtrDerivedFrom(llvm::Value *Derived, llvm::Value *Base);
  bool isInstructionNear(llvm::Instruction *I1, llvm::Value *I2, unsigned threshold);
  unsigned getApproximateBlockDistance(llvm::BasicBlock *BB1, llvm::BasicBlock *BB2);
  
  double analyzeMallocStatic(llvm::CallInst *CI, llvm::Function &F,
                               llvm::LoopAnalysis::Result &LA,
                               llvm::ScalarEvolution &SE,
                               llvm::AAResults &AA,
                               llvm::MemorySSA &MSSA,
                               llvm::LoopAccessAnalysis::Result &LAA,
                               MallocRecord &MR);
  void matchFreeCalls(FunctionMallocInfo &FMI, std::vector<llvm::CallInst *> &freeCalls);
  // 合并了原 findBasePointer 与 resolveBasePointer：用于追溯基地址
  llvm::Value* resolveBasePointer(llvm::Value *V);
  void explorePointerUsers(llvm::Value *RootPtr, llvm::Value *V,
                           llvm::LoopAnalysis::Result &LA,
                           llvm::ScalarEvolution &SE,
                           llvm::AAResults &AA,
                           llvm::MemorySSA &MSSA,
                           llvm::LoopAccessAnalysis::Result &LAA,
                           double &Score,
                           MallocRecord &MR,
                           std::unordered_set<llvm::Value *> &Visited);
  double computeAccessScore(llvm::Instruction *I,
                            llvm::LoopAnalysis::Result &LA,
                            llvm::ScalarEvolution &SE,
                            llvm::AAResults &AA,
                            llvm::MemorySSA &MSSA,
                            llvm::LoopAccessAnalysis::Result &LAA,
                            bool isWrite,
                            MallocRecord &MR);
  uint64_t getLoopTripCount(llvm::Loop *L, llvm::ScalarEvolution &SE);
  bool detectParallelRuntime(llvm::Function &F);
  double computeBandwidthScore(uint64_t approximateBytes, double approximateTime);
  double computeMemorySSAStructureScore(const llvm::Instruction *I, llvm::MemorySSA &MSSA);
  bool isThreadIDRelated(llvm::Value *V);
  bool isStreamingAccess(llvm::Value *Ptr, llvm::ScalarEvolution &SE, llvm::AAResults &AA, llvm::Loop *L);
  bool isVectorizedAccess(llvm::Value *Ptr, llvm::ScalarEvolution &SE, llvm::AAResults &AA, llvm::Loop *L);
  
  // 添加新的向量化识别函数
  bool isVectorizedInstruction(llvm::Instruction *I);
  bool detectSIMDIntrinsics(llvm::Function &F);
  bool isVectorLoopPattern(llvm::Loop *L, llvm::ScalarEvolution &SE);
  bool hasVectorOperations(llvm::Value *V, std::set<llvm::Value*> &Visited);
  int getVectorWidth(llvm::Type *Ty);
  bool isLoopMarkedVectorizable(const llvm::Loop *L);
  // 嵌套循环分析
  double analyzeNestedLoops(llvm::Loop *L, llvm::Value *Ptr, llvm::ScalarEvolution &SE, llvm::LoopAnalysis::Result &LA);
  bool isMemoryIntensiveLoop(llvm::Loop *L);
  double computeLoopNestingScore(llvm::Loop *L, llvm::LoopAnalysis::Result &LA);
  // 添加步长分析函数声明
  StrideType analyzeGEPStride(llvm::GetElementPtrInst *GEP, llvm::ScalarEvolution &SE);
  // 辅助函数：尝试从 Value 中提取常量大小
  std::optional<uint64_t> getConstantAllocSize(llvm::Value *V, std::set<llvm::Value*> &Visited);
  
};

} // namespace MyAdvancedHBM

#endif // MY_FUNCTION_ANALYSIS_PASS_H