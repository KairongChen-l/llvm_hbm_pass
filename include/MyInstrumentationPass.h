#ifndef MY_INSTRUMENTATION_PASS_H
#define MY_INSTRUMENTATION_PASS_H

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/Passes/PassBuilder.h"
#include <vector>

namespace MyAdvancedHBM
{

  class MyInstrumentationPass : public llvm::PassInfoMixin<MyInstrumentationPass>
  {
  public:
    llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &FAM);

  private:
    void instrumentLoadOrStore(llvm::Instruction *I, bool isStore);
    uint64_t getAccessSize(llvm::Instruction *I) const;
    llvm::Value *getThreadID(llvm::IRBuilder<> &Builder, llvm::Module *M);
  };

} // namespace MyAdvancedHBM

#endif // MY_INSTRUMENTATION_PASS_H
