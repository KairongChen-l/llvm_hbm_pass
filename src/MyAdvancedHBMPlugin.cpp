#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "MyInstrumentationPass.h"
#include "MyFunctionAnalysisPass.h"
#include "MyModuleTransformPass.h"

using namespace llvm;
using namespace MyAdvancedHBM;

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION,
    "MyAdvancedHBMPlugin",
    LLVM_VERSION_STRING,
    [](PassBuilder &PB) {
      // 注册额外的分析：包括 MyFunctionAnalysisPass 以及其它基础分析
      PB.registerAnalysisRegistrationCallback(
          [&](FunctionAnalysisManager &FAM) {
            FAM.registerPass([] { return MyFunctionAnalysisPass(); });
            FAM.registerPass([] { return LoopAnalysis(); });
            FAM.registerPass([] { return ScalarEvolutionAnalysis(); });
            FAM.registerPass([] { return MemorySSAAnalysis(); });
            FAM.registerPass([] { return LoopAccessAnalysis(); });
          });
      // 注册 instrumentation pass
      PB.registerPipelineParsingCallback(
          [&](StringRef Name, FunctionPassManager &FPM,
              ArrayRef<PassBuilder::PipelineElement>) {
            if (Name == "my-instrument") {
              FPM.addPass(MyInstrumentationPass());
              return true;
            }
            return false;
          });
      // 注册 module transform pass
      PB.registerPipelineParsingCallback(
          [&](StringRef Name, ModulePassManager &MPM,
              ArrayRef<PassBuilder::PipelineElement>) {
            if (Name == "my-hbm-transform") {
              MPM.addPass(MyModuleTransformPass());
              return true;
            }
            return false;
          });
    }
  };
}
