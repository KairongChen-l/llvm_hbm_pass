#ifndef MY_MODULE_TRANSFORM_PASS_H
#define MY_MODULE_TRANSFORM_PASS_H

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include <string>
#include "MyFunctionAnalysisPass.h"

namespace MyAdvancedHBM
{

  class MyModuleTransformPass : public llvm::PassInfoMixin<MyModuleTransformPass>
  {
  public:
    MyModuleTransformPass() = default;
    static llvm::cl::opt<std::string> HBMReportFile;
    static llvm::cl::opt<std::string> ExternalProfileFile;
    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM);

  private:
    static constexpr uint64_t DefaultHBMCapacity = 1ULL << 30; // 1GB
    void loadExternalProfile(llvm::Module &M, llvm::SmallVectorImpl<MallocRecord *> &AllMallocs);
    void processMallocRecords(llvm::Module &M, llvm::SmallVectorImpl<MallocRecord *> &AllMallocs);
    void generateReport(const llvm::Module &M, llvm::ArrayRef<MallocRecord *> AllMallocs, bool JSONOutput);
    std::string getSourceLocation(llvm::CallInst *CI);
  };

} // namespace MyAdvancedHBM

#endif // MY_MODULE_TRANSFORM_PASS_H
