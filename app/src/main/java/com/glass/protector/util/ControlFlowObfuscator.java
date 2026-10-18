package com.glass.protector.util;

import org.jf.dexlib2.AccessFlags;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.TryBlock;
import org.jf.dexlib2.iface.debug.DebugItem;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.builder.MutableMethodImplementation;
import org.jf.dexlib2.builder.Label;
import org.jf.dexlib2.builder.BuilderInstruction;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.rewriter.DexRewriter;
import org.jf.dexlib2.rewriter.RewriterModule;
import org.jf.dexlib2.rewriter.Rewriter;
import org.jf.dexlib2.rewriter.Rewriters;
import org.jf.dexlib2.immutable.ImmutableMethod;
import org.jf.dexlib2.writer.io.FileDataStore;
import org.jf.dexlib2.writer.pool.DexPool;

import java.io.File;
import java.util.List;
import java.util.Random;

/**
 * 控制流混淆器：基于 dexlib2 对 DEX 做字节码级指令流改写。
 *
 * 核心机制：
 *   1. 扩展 register_count：R -> R+1，专用混淆寄存器 obfReg = R - 参数数（重映射后空闲）
 *   2. 参数重映射：所有 >= threshold 的寄存器号 +1（参数上移，避免错位）
 *   3. 不透明谓词 + 死代码：方法开头插入恒真跳转 + 永不执行的算术死代码块
 *   4. 算术等价混淆：死代码块内的冗余 int 运算
 *
 * 安全约束：
 *   - 只用 obfReg 一个专用寄存器，不碰原方法的参数/临时寄存器
 *   - 死代码块以 goto 终止，不产生 fall-through 到真实代码的路径
 *   - 跳过 <init>/<clinit>/abstract/native/无实现/过短方法
 *   - 清除 debug items（避免参数寄存器重映射后 debug 信息错位，同时增大反编译难度）
 */
public class ControlFlowObfuscator {
    private static final int MIN_INSTRUCTIONS = 8;

    private static final class ExtendedImpl implements MethodImplementation {
        final MethodImplementation inner;
        final int newCount;
        ExtendedImpl(MethodImplementation inner, int newCount) {
            this.inner = inner;
            this.newCount = newCount;
        }
        @Override public int getRegisterCount() { return newCount; }
        @Override public Iterable<? extends Instruction> getInstructions() { return inner.getInstructions(); }
        @Override public List<? extends TryBlock<? extends org.jf.dexlib2.iface.ExceptionHandler>> getTryBlocks() {
            return inner.getTryBlocks();
        }
        @Override public Iterable<? extends DebugItem> getDebugItems() {
            return java.util.Collections.emptyList();
        }
    }

    public static void obfuscate(File inputDex, File outputDex, long seed) throws Exception {
        Opcodes opcodes = Opcodes.forApi(24);
        DexBackedDexFile dex = DexFileFactory.loadDexFile(inputDex, opcodes);

        final Random rng = new Random(seed);
        final int[] counters = new int[6];

        DexRewriter rewriter = new DexRewriter(new RewriterModule() {
            @Override
            public Rewriter<Method> getMethodRewriter(Rewriters rewriters) {
                return method -> obfuscateMethod(method, rng, counters);
            }
        });

        DexFile out = rewriter.getDexFileRewriter().rewrite(dex);
        DexPool.writeTo(new FileDataStore(outputDex), out);
    }

    private static Method obfuscateMethod(Method method, Random rng, int[] counters) {
        MethodImplementation impl = method.getImplementation();
        if (impl == null) { counters[4]++; return method; }

        int flags = method.getAccessFlags();
        String name = method.getName();
        if (name.equals("<init>") || name.equals("<clinit>")
                || AccessFlags.ABSTRACT.isSet(flags)
                || AccessFlags.NATIVE.isSet(flags)) {
            counters[3]++;
            return method;
        }

        int R = impl.getRegisterCount();
        if (R < 2) { counters[2]++; return method; }

        int p = method.getParameterTypes().size();
        if (!AccessFlags.STATIC.isSet(flags)) p++;
        int threshold = R - p;

        int n = instructionCount(impl);
        counters[0]++;
        if (n < MIN_INSTRUCTIONS) { counters[2]++; return method; }

        MutableMethodImplementation m = new MutableMethodImplementation(impl);
        remapRegisters(m, threshold);
        insertObfuscation(m, threshold, rng);

        MethodImplementation newImpl = new ExtendedImpl(m, R + 1);

        counters[1]++;
        return new ImmutableMethod(
                method.getDefiningClass(),
                name,
                method.getParameters(),
                method.getReturnType(),
                flags,
                method.getAnnotations(),
                method.getHiddenApiRestrictions(),
                newImpl);
    }

    private static int instructionCount(MethodImplementation impl) {
        int n = 0;
        for (Instruction ins : impl.getInstructions()) n++;
        return n;
    }

    private static int map(int r, int threshold) {
        return r >= threshold ? r + 1 : r;
    }

    private static void remapRegisters(MutableMethodImplementation m, int threshold) {
        List<BuilderInstruction> insns = m.getInstructions();
        for (int i = 0; i < insns.size(); i++) {
            BuilderInstruction bi = insns.get(i);
            BuilderInstruction r = remap(bi, threshold);
            if (r != bi) m.replaceInstruction(i, r);
        }
    }

    private static BuilderInstruction remap(BuilderInstruction ins, int threshold) {
        Opcode op = ins.getOpcode();
        if (ins instanceof BuilderInstruction11n) {
            BuilderInstruction11n i = (BuilderInstruction11n) ins;
            return new BuilderInstruction11n(op, map(i.getRegisterA(), threshold), i.getNarrowLiteral());
        }
        if (ins instanceof BuilderInstruction11x) {
            BuilderInstruction11x i = (BuilderInstruction11x) ins;
            return new BuilderInstruction11x(op, map(i.getRegisterA(), threshold));
        }
        if (ins instanceof BuilderInstruction12x) {
            BuilderInstruction12x i = (BuilderInstruction12x) ins;
            return new BuilderInstruction12x(op, map(i.getRegisterA(), threshold), map(i.getRegisterB(), threshold));
        }
        if (ins instanceof BuilderInstruction21s) {
            BuilderInstruction21s i = (BuilderInstruction21s) ins;
            return new BuilderInstruction21s(op, map(i.getRegisterA(), threshold), i.getNarrowLiteral());
        }
        if (ins instanceof BuilderInstruction21t) {
            BuilderInstruction21t i = (BuilderInstruction21t) ins;
            return new BuilderInstruction21t(op, map(i.getRegisterA(), threshold), i.getTarget());
        }
        if (ins instanceof BuilderInstruction22b) {
            BuilderInstruction22b i = (BuilderInstruction22b) ins;
            return new BuilderInstruction22b(op, map(i.getRegisterA(), threshold), map(i.getRegisterB(), threshold), i.getNarrowLiteral());
        }
        if (ins instanceof BuilderInstruction22s) {
            BuilderInstruction22s i = (BuilderInstruction22s) ins;
            return new BuilderInstruction22s(op, map(i.getRegisterA(), threshold), map(i.getRegisterB(), threshold), i.getNarrowLiteral());
        }
        if (ins instanceof BuilderInstruction22t) {
            BuilderInstruction22t i = (BuilderInstruction22t) ins;
            return new BuilderInstruction22t(op, map(i.getRegisterA(), threshold), map(i.getRegisterB(), threshold), i.getTarget());
        }
        if (ins instanceof BuilderInstruction22x) {
            BuilderInstruction22x i = (BuilderInstruction22x) ins;
            return new BuilderInstruction22x(op, map(i.getRegisterA(), threshold), map(i.getRegisterB(), threshold));
        }
        if (ins instanceof BuilderInstruction23x) {
            BuilderInstruction23x i = (BuilderInstruction23x) ins;
            return new BuilderInstruction23x(op, map(i.getRegisterA(), threshold), map(i.getRegisterB(), threshold), map(i.getRegisterC(), threshold));
        }
        if (ins instanceof BuilderInstruction31i) {
            BuilderInstruction31i i = (BuilderInstruction31i) ins;
            return new BuilderInstruction31i(op, map(i.getRegisterA(), threshold), (int) i.getWideLiteral());
        }
        if (ins instanceof BuilderInstruction31t) {
            BuilderInstruction31t i = (BuilderInstruction31t) ins;
            return new BuilderInstruction31t(op, map(i.getRegisterA(), threshold), i.getTarget());
        }
        if (ins instanceof BuilderInstruction32x) {
            BuilderInstruction32x i = (BuilderInstruction32x) ins;
            return new BuilderInstruction32x(op, map(i.getRegisterA(), threshold), map(i.getRegisterB(), threshold));
        }
        if (ins instanceof BuilderInstruction35c) {
            BuilderInstruction35c i = (BuilderInstruction35c) ins;
            return new BuilderInstruction35c(op, i.getRegisterCount(),
                    map(i.getRegisterC(), threshold), map(i.getRegisterD(), threshold),
                    map(i.getRegisterE(), threshold), map(i.getRegisterF(), threshold),
                    map(i.getRegisterG(), threshold), i.getReference());
        }
        if (ins instanceof BuilderInstruction3rc) {
            BuilderInstruction3rc i = (BuilderInstruction3rc) ins;
            return new BuilderInstruction3rc(op, map(i.getStartRegister(), threshold), i.getRegisterCount(), i.getReference());
        }
        return ins;
    }

    private static void insertObfuscation(MutableMethodImplementation m, int obfReg, Random rng) {
        Label real = m.newLabelForIndex(0);

        m.addInstruction(0, new BuilderInstruction10t(Opcode.GOTO, real));

        int extra = 1 + rng.nextInt(3);
        for (int k = 0; k < extra; k++) {
            switch (rng.nextInt(4)) {
                case 0:
                    m.addInstruction(0, new BuilderInstruction22b(Opcode.ADD_INT_LIT8, obfReg, obfReg, rng.nextInt(0x7F)));
                    break;
                case 1:
                    m.addInstruction(0, new BuilderInstruction22b(Opcode.XOR_INT_LIT8, obfReg, obfReg, rng.nextInt(0x7F)));
                    break;
                case 2:
                    m.addInstruction(0, new BuilderInstruction22s(Opcode.ADD_INT_LIT16, obfReg, obfReg, rng.nextInt(0x7FFF)));
                    break;
                default:
                    m.addInstruction(0, new BuilderInstruction23x(Opcode.XOR_INT, obfReg, obfReg, obfReg));
                    break;
            }
        }

        m.addInstruction(0, new BuilderInstruction22b(Opcode.XOR_INT_LIT8, obfReg, obfReg, rng.nextInt(0x7F)));
        m.addInstruction(0, new BuilderInstruction22s(Opcode.ADD_INT_LIT16, obfReg, obfReg, rng.nextInt(0x7FFF)));
        m.addInstruction(0, new BuilderInstruction31i(Opcode.CONST, obfReg, rng.nextInt(0xFFFF)));

        m.addInstruction(0, new BuilderInstruction21t(Opcode.IF_EQZ, obfReg, real));
        m.addInstruction(0, new BuilderInstruction11n(Opcode.CONST_4, obfReg, 0));
    }
}
