#ifndef MY_HBM_OPTIONS_H
#define MY_HBM_OPTIONS_H

#include "llvm/Support/CommandLine.h"

namespace MyHBMOptions {

static llvm::cl::opt<double> HBMThreshold(
    "hbm-threshold",
    llvm::cl::desc("Score threshold for HBM usage"),
    llvm::cl::init(50.0));

static llvm::cl::opt<double> ParallelBonus(
    "hbm-parallel-bonus",
    llvm::cl::desc("Extra score for parallel usage"),
    llvm::cl::init(20.0));

static llvm::cl::opt<double> StreamBonus(
    "hbm-stream-bonus",
    llvm::cl::desc("Extra score for streaming usage"),
    llvm::cl::init(10.0));

static llvm::cl::opt<double> VectorBonus(
    "hbm-vector-bonus",
    llvm::cl::desc("Extra score for vectorized usage"),
    llvm::cl::init(5.0));

static llvm::cl::opt<double> AccessBaseRead(
    "hbm-access-base-read",
    llvm::cl::desc("Base read score"),
    llvm::cl::init(5.0));

static llvm::cl::opt<double> AccessBaseWrite(
    "hbm-access-base-write",
    llvm::cl::desc("Base write score"),
    llvm::cl::init(8.0));

static llvm::cl::opt<double> BandwidthScale(
    "hbm-bandwidth-scale",
    llvm::cl::desc("Scaling factor for estimated bandwidth usage"),
    llvm::cl::init(1.0));

} // namespace MyHBMOptions

#endif // MY_HBM_OPTIONS_H
