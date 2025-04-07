#include "MyInstrumentationPass.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace MyAdvancedHBM;

llvm::PreservedAnalyses MyInstrumentationPass::run(Function &F, FunctionAnalysisManager &FAM) {
  if (F.isDeclaration())
    return PreservedAnalyses::all();

  // 在函数入口处插入 record_start_time()
  IRBuilder<> EntryBuilder(&*F.getEntryBlock().getFirstInsertionPt());
  FunctionCallee StartFn = F.getParent()->getOrInsertFunction(
      "record_start_time",
      FunctionType::get(Type::getVoidTy(F.getContext()), false));
  EntryBuilder.CreateCall(StartFn);

  std::vector<Instruction *> Insts;
  for (auto &BB : F) {
    for (auto &I : BB) {
      if (isa<LoadInst>(I) || isa<StoreInst>(I))
        Insts.push_back(&I);
    }
  }

  // 对每个 Load/Store 指令进行插桩
  for (auto *I : Insts) {
    if (auto *LD = dyn_cast<LoadInst>(I))
      instrumentLoadOrStore(LD, false);
    else if (auto *ST = dyn_cast<StoreInst>(I))
      instrumentLoadOrStore(ST, true);
  }

  // 在所有返回点插入 record_end_time()（也可进一步优化为统一出口）
  for (auto &BB : F) {
    if (ReturnInst *RetInst = dyn_cast<ReturnInst>(BB.getTerminator())) {
      IRBuilder<> RetBuilder(RetInst);
      FunctionCallee EndFn = F.getParent()->getOrInsertFunction(
          "record_end_time",
          FunctionType::get(Type::getVoidTy(F.getContext()), false));
      RetBuilder.CreateCall(EndFn);
    }
  }

  return PreservedAnalyses::none();
}

void MyInstrumentationPass::instrumentLoadOrStore(Instruction *I, bool isStore) {
  Module *M = I->getModule();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> Builder(I);

  Value *Addr = nullptr;
  if (auto *LD = dyn_cast<LoadInst>(I))
    Addr = LD->getPointerOperand();
  else if (auto *ST = dyn_cast<StoreInst>(I))
    Addr = ST->getPointerOperand();
  if (!Addr) return;

  Type *VoidTy    = Type::getVoidTy(Ctx);
  Type *Int8PtrTy = Type::getInt8PtrTy(Ctx);
  Type *BoolTy    = Type::getInt1Ty(Ctx);

  // 获取 record_mem_access 函数，其签名为 void record_mem_access(void*, bool)
  FunctionCallee Fn = M->getOrInsertFunction(
      "record_mem_access",
      FunctionType::get(VoidTy, {Int8PtrTy, BoolTy}, false));

  Value *castAddr = Builder.CreatePointerCast(Addr, Int8PtrTy);
  Value *bIsWrite = Builder.getInt1(isStore);
  Builder.CreateCall(Fn, {castAddr, bIsWrite});

  // 插桩调用 record_access_stats(size)
  uint64_t size = getAccessSize(I);
  FunctionCallee RecFn = M->getOrInsertFunction(
      "record_access_stats",
      FunctionType::get(VoidTy, {Type::getInt64Ty(Ctx)}, false));
  Builder.CreateCall(RecFn, {Builder.getInt64(size)});
}

uint64_t MyInstrumentationPass::getAccessSize(Instruction *I) const {
  const DataLayout &DL = I->getModule()->getDataLayout();
  Type *accessedTy = nullptr;
  if (auto *LD = dyn_cast<LoadInst>(I))
    accessedTy = LD->getType();
  else if (auto *ST = dyn_cast<StoreInst>(I))
    accessedTy = ST->getValueOperand()->getType();

  if (!accessedTy || !accessedTy->isSized())
    return 0;
  return DL.getTypeStoreSize(accessedTy);
}

Value* MyInstrumentationPass::getThreadID(IRBuilder<> &Builder, Module *M) {
  // TODO: 根据需求完善获取线程ID的逻辑
  return nullptr;
}
