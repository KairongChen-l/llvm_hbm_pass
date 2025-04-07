#ifndef MY_FUNCTION_ANALYSIS_PASS_H
#define MY_FUNCTION_ANALYSIS_PASS_H

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/MemorySSA.h"
#include "llvm/Analysis/LoopAccessAnalysis.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/CommandLine.h"
#include <set>
#include <unordered_set>
#include <queue>
#include <optional>
#include <vector>
#include <string>
namespace MyAdvancedHBM {

// 用于记录单个 malloc 调用点的分析结果
struct MallocRecord {
  llvm::CallInst        *MallocCall = nullptr; //malloc指令
  double                Score = 0.0;           //综合评分
  uint64_t              AllocSize = 0;         //分配大小
  bool                  UserForcedHot = false; //用户强制热数据
  bool                  UnmatchedFree = false; //未匹配的free调用
  std::vector<llvm::CallInst *> FreeCalls;     //与malloc匹配的free调用
  uint64_t              DynamicAccessCount = 0;//动态分析计数
  // 估算带宽
  double                EstimatedBandwidth = 0.0;
  uint64_t              AccessedBytes = 0;
  double                AccessTime = 0;
  double                BandwidthScore = 0.0;
  // 模式标志
  bool                  IsStreamAccess = false;
  bool                  IsVectorized = false;
  bool                  IsParallel = false;
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
  
private:
  friend llvm::AnalysisInfoMixin<MyFunctionAnalysisPass>;
  static llvm::AnalysisKey Key;
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

  // 辅助函数：尝试从 Value 中提取常量大小
  std::optional<uint64_t> getConstantAllocSize(llvm::Value *V, std::set<llvm::Value*> &Visited);
};

} // namespace MyAdvancedHBM

#endif // MY_FUNCTION_ANALYSIS_PASS_H
