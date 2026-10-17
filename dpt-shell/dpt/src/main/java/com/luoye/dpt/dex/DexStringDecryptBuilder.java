package com.luoye.dpt.dex;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction12x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22b;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction23x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction35c;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference;

import java.util.Collections;

/**
 * Emits inline XOR string decryption bytecode into a helper method.
 */
public final class DexStringDecryptBuilder {

    private static final String JAVA_STRING = "Ljava/lang/String;";
    private static final String CHAR_ARRAY = "[C";

    private static final ImmutableMethodReference TO_CHAR_ARRAY = new ImmutableMethodReference(
            JAVA_STRING, "toCharArray", Collections.emptyList(), CHAR_ARRAY);
    private static final ImmutableMethodReference STRING_INIT = new ImmutableMethodReference(
            JAVA_STRING, "<init>", Collections.singletonList(CHAR_ARRAY), "V");

    private DexStringDecryptBuilder() {
    }

    public static void emitDecrypt(MutableMethodImplementation impl,
                                   int outReg,
                                   String encrypted,
                                   int arrReg,
                                   int idxReg,
                                   int keyReg,
                                   int lenReg,
                                   int tmpReg) {
        impl.addInstruction(new BuilderInstruction21c(
                Opcode.CONST_STRING, arrReg, new ImmutableStringReference(encrypted)));
        impl.addInstruction(new BuilderInstruction35c(
                Opcode.INVOKE_VIRTUAL, 1, arrReg, 0, 0, 0, 0, TO_CHAR_ARRAY));
        impl.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, arrReg));

        impl.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, idxReg, 0));
        impl.addInstruction(new BuilderInstruction12x(Opcode.ARRAY_LENGTH, lenReg, arrReg));

        int loopStartIndex = impl.getInstructions().size();
        impl.addInstruction(new BuilderInstruction10x(Opcode.NOP));

        impl.addInstruction(new BuilderInstruction23x(Opcode.AGET_CHAR, tmpReg, arrReg, idxReg));
        impl.addInstruction(new BuilderInstruction23x(Opcode.XOR_INT, tmpReg, tmpReg, keyReg));
        impl.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_CHAR, tmpReg, tmpReg));
        impl.addInstruction(new BuilderInstruction23x(Opcode.APUT_CHAR, tmpReg, arrReg, idxReg));
        impl.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, idxReg, idxReg, 1));

        Label loopStart = impl.newLabelForIndex(loopStartIndex);
        impl.addInstruction(new BuilderInstruction10t(Opcode.GOTO, loopStart));

        int endIndex = impl.getInstructions().size();
        impl.addInstruction(new BuilderInstruction21c(
                Opcode.NEW_INSTANCE, outReg, new ImmutableTypeReference(JAVA_STRING)));
        impl.addInstruction(new BuilderInstruction35c(
                Opcode.INVOKE_DIRECT, 2, outReg, arrReg, 0, 0, 0, STRING_INIT));

        Label loopEnd = impl.newLabelForIndex(endIndex);
        impl.replaceInstruction(loopStartIndex,
                new BuilderInstruction22t(Opcode.IF_GE, idxReg, lenReg, loopEnd));
    }
}
