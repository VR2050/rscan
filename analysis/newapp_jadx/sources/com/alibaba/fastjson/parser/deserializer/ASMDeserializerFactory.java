package com.alibaba.fastjson.parser.deserializer;

import com.alibaba.fastjson.asm.ClassWriter;
import com.alibaba.fastjson.asm.FieldWriter;
import com.alibaba.fastjson.asm.Label;
import com.alibaba.fastjson.asm.MethodVisitor;
import com.alibaba.fastjson.asm.MethodWriter;
import com.alibaba.fastjson.asm.Opcodes;
import com.alibaba.fastjson.asm.Type;
import com.alibaba.fastjson.parser.DefaultJSONParser;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.JSONLexer;
import com.alibaba.fastjson.parser.JSONLexerBase;
import com.alibaba.fastjson.parser.ParseContext;
import com.alibaba.fastjson.parser.ParserConfig;
import com.alibaba.fastjson.parser.SymbolTable;
import com.alibaba.fastjson.util.ASMClassLoader;
import com.alibaba.fastjson.util.ASMUtils;
import com.alibaba.fastjson.util.FieldInfo;
import com.alibaba.fastjson.util.JavaBeanInfo;
import com.alibaba.fastjson.util.TypeUtils;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class ASMDeserializerFactory implements Opcodes {
    public static final String DefaultJSONParser = ASMUtils.type(DefaultJSONParser.class);
    public static final String JSONLexerBase = ASMUtils.type(JSONLexerBase.class);
    public final ASMClassLoader classLoader;
    public final AtomicLong seed = new AtomicLong();

    public ASMDeserializerFactory(ClassLoader classLoader) {
        this.classLoader = classLoader instanceof ASMClassLoader ? (ASMClassLoader) classLoader : new ASMClassLoader(classLoader);
    }

    private void _batchSet(Context context, MethodVisitor methodVisitor) {
        _batchSet(context, methodVisitor, true);
    }

    private void _createInstance(Context context, MethodVisitor methodVisitor) {
        Constructor<?> constructor = context.beanInfo.defaultConstructor;
        if (Modifier.isPublic(constructor.getModifiers())) {
            methodVisitor.visitTypeInsn(Opcodes.NEW, ASMUtils.type(context.getInstClass()));
            methodVisitor.visitInsn(89);
            methodVisitor.visitMethodInsn(Opcodes.INVOKESPECIAL, ASMUtils.type(constructor.getDeclaringClass()), "<init>", "()V");
            methodVisitor.visitVarInsn(58, context.var("instance"));
            return;
        }
        methodVisitor.visitVarInsn(25, 0);
        methodVisitor.visitVarInsn(25, 1);
        methodVisitor.visitVarInsn(25, 0);
        methodVisitor.visitFieldInsn(180, ASMUtils.type(JavaBeanDeserializer.class), "clazz", "Ljava/lang/Class;");
        methodVisitor.visitMethodInsn(Opcodes.INVOKESPECIAL, ASMUtils.type(JavaBeanDeserializer.class), "createInstance", C1499a.m582D(C1499a.m586H("(L"), DefaultJSONParser, ";Ljava/lang/reflect/Type;)Ljava/lang/Object;"));
        methodVisitor.visitTypeInsn(Opcodes.CHECKCAST, ASMUtils.type(context.getInstClass()));
        methodVisitor.visitVarInsn(58, context.var("instance"));
    }

    private void _deserObject(Context context, MethodVisitor methodVisitor, FieldInfo fieldInfo, Class<?> cls, int i2) {
        _getFieldDeser(context, methodVisitor, fieldInfo);
        Label label = new Label();
        Label label2 = new Label();
        if ((fieldInfo.parserFeatures & Feature.SupportArrayToBean.mask) != 0) {
            methodVisitor.visitInsn(89);
            methodVisitor.visitTypeInsn(Opcodes.INSTANCEOF, ASMUtils.type(JavaBeanDeserializer.class));
            methodVisitor.visitJumpInsn(Opcodes.IFEQ, label);
            methodVisitor.visitTypeInsn(Opcodes.CHECKCAST, ASMUtils.type(JavaBeanDeserializer.class));
            methodVisitor.visitVarInsn(25, 1);
            if (fieldInfo.fieldType instanceof Class) {
                methodVisitor.visitLdcInsn(Type.getType(ASMUtils.desc(fieldInfo.fieldClass)));
            } else {
                methodVisitor.visitVarInsn(25, 0);
                methodVisitor.visitLdcInsn(Integer.valueOf(i2));
                methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ASMUtils.type(JavaBeanDeserializer.class), "getFieldType", "(I)Ljava/lang/reflect/Type;");
            }
            methodVisitor.visitLdcInsn(fieldInfo.name);
            methodVisitor.visitLdcInsn(Integer.valueOf(fieldInfo.parserFeatures));
            methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ASMUtils.type(JavaBeanDeserializer.class), "deserialze", C1499a.m582D(C1499a.m586H("(L"), DefaultJSONParser, ";Ljava/lang/reflect/Type;Ljava/lang/Object;I)Ljava/lang/Object;"));
            methodVisitor.visitTypeInsn(Opcodes.CHECKCAST, ASMUtils.type(cls));
            methodVisitor.visitVarInsn(58, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
            methodVisitor.visitJumpInsn(Opcodes.GOTO, label2);
            methodVisitor.visitLabel(label);
        }
        methodVisitor.visitVarInsn(25, 1);
        if (fieldInfo.fieldType instanceof Class) {
            methodVisitor.visitLdcInsn(Type.getType(ASMUtils.desc(fieldInfo.fieldClass)));
        } else {
            methodVisitor.visitVarInsn(25, 0);
            methodVisitor.visitLdcInsn(Integer.valueOf(i2));
            methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ASMUtils.type(JavaBeanDeserializer.class), "getFieldType", "(I)Ljava/lang/reflect/Type;");
        }
        methodVisitor.visitLdcInsn(fieldInfo.name);
        methodVisitor.visitMethodInsn(Opcodes.INVOKEINTERFACE, ASMUtils.type(ObjectDeserializer.class), "deserialze", C1499a.m582D(C1499a.m586H("(L"), DefaultJSONParser, ";Ljava/lang/reflect/Type;Ljava/lang/Object;)Ljava/lang/Object;"));
        methodVisitor.visitTypeInsn(Opcodes.CHECKCAST, ASMUtils.type(cls));
        methodVisitor.visitVarInsn(58, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
        methodVisitor.visitLabel(label2);
    }

    private void _deserialize_endCheck(Context context, MethodVisitor methodVisitor, Label label) {
        methodVisitor.visitIntInsn(21, context.var("matchedCount"));
        methodVisitor.visitJumpInsn(Opcodes.IFLE, label);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, JSONLexerBase, "token", "()I");
        methodVisitor.visitLdcInsn(13);
        methodVisitor.visitJumpInsn(Opcodes.IF_ICMPNE, label);
        _quickNextTokenComma(context, methodVisitor);
    }

    /* JADX WARN: Removed duplicated region for block: B:73:0x0bf0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void _deserialze(com.alibaba.fastjson.asm.ClassWriter r24, com.alibaba.fastjson.parser.deserializer.ASMDeserializerFactory.Context r25) {
        /*
            Method dump skipped, instructions count: 3526
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.deserializer.ASMDeserializerFactory._deserialze(com.alibaba.fastjson.asm.ClassWriter, com.alibaba.fastjson.parser.deserializer.ASMDeserializerFactory$Context):void");
    }

    private void _deserialzeArrayMapping(ClassWriter classWriter, Context context) {
        Class<JavaBeanDeserializer> cls;
        int i2;
        MethodWriter methodWriter;
        Class<JavaBeanDeserializer> cls2 = JavaBeanDeserializer.class;
        StringBuilder m586H = C1499a.m586H("(L");
        String str = DefaultJSONParser;
        MethodWriter methodWriter2 = new MethodWriter(classWriter, 1, "deserialzeArrayMapping", C1499a.m582D(m586H, str, ";Ljava/lang/reflect/Type;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"), null, null);
        defineVarLexer(context, methodWriter2);
        methodWriter2.visitVarInsn(25, context.var("lexer"));
        methodWriter2.visitVarInsn(25, 1);
        methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "getSymbolTable", "()" + ASMUtils.desc((Class<?>) SymbolTable.class));
        String str2 = JSONLexerBase;
        StringBuilder m586H2 = C1499a.m586H(ChineseToPinyinResource.Field.LEFT_BRACKET);
        m586H2.append(ASMUtils.desc((Class<?>) SymbolTable.class));
        m586H2.append(")Ljava/lang/String;");
        methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str2, "scanTypeName", m586H2.toString());
        methodWriter2.visitVarInsn(58, context.var("typeName"));
        Label label = new Label();
        methodWriter2.visitVarInsn(25, context.var("typeName"));
        methodWriter2.visitJumpInsn(Opcodes.IFNULL, label);
        methodWriter2.visitVarInsn(25, 1);
        methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "getConfig", "()" + ASMUtils.desc((Class<?>) ParserConfig.class));
        methodWriter2.visitVarInsn(25, 0);
        methodWriter2.visitFieldInsn(180, ASMUtils.type(cls2), "beanInfo", ASMUtils.desc((Class<?>) JavaBeanInfo.class));
        methodWriter2.visitVarInsn(25, context.var("typeName"));
        String type = ASMUtils.type(cls2);
        StringBuilder m586H3 = C1499a.m586H(ChineseToPinyinResource.Field.LEFT_BRACKET);
        m586H3.append(ASMUtils.desc((Class<?>) ParserConfig.class));
        m586H3.append(ASMUtils.desc((Class<?>) JavaBeanInfo.class));
        m586H3.append("Ljava/lang/String;)");
        m586H3.append(ASMUtils.desc(cls2));
        methodWriter2.visitMethodInsn(Opcodes.INVOKESTATIC, type, "getSeeAlso", m586H3.toString());
        methodWriter2.visitVarInsn(58, context.var("userTypeDeser"));
        methodWriter2.visitVarInsn(25, context.var("userTypeDeser"));
        methodWriter2.visitTypeInsn(Opcodes.INSTANCEOF, ASMUtils.type(cls2));
        methodWriter2.visitJumpInsn(Opcodes.IFEQ, label);
        methodWriter2.visitVarInsn(25, context.var("userTypeDeser"));
        methodWriter2.visitVarInsn(25, 1);
        methodWriter2.visitVarInsn(25, 2);
        methodWriter2.visitVarInsn(25, 3);
        methodWriter2.visitVarInsn(25, 4);
        methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ASMUtils.type(cls2), "deserialzeArrayMapping", C1499a.m639y("(L", str, ";Ljava/lang/reflect/Type;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"));
        methodWriter2.visitInsn(Opcodes.ARETURN);
        methodWriter2.visitLabel(label);
        _createInstance(context, methodWriter2);
        FieldInfo[] fieldInfoArr = context.beanInfo.sortedFields;
        int length = fieldInfoArr.length;
        int i3 = 0;
        while (i3 < length) {
            boolean z = i3 == length + (-1);
            int i4 = z ? 93 : 44;
            FieldInfo fieldInfo = fieldInfoArr[i3];
            Class<?> cls3 = fieldInfo.fieldClass;
            java.lang.reflect.Type type2 = fieldInfo.fieldType;
            FieldInfo[] fieldInfoArr2 = fieldInfoArr;
            int i5 = length;
            if (cls3 == Byte.TYPE || cls3 == Short.TYPE || cls3 == Integer.TYPE) {
                cls = cls2;
                i2 = i3;
                methodWriter = methodWriter2;
                methodWriter.visitVarInsn(25, context.var("lexer"));
                methodWriter.visitVarInsn(16, i4);
                methodWriter.visitVarInsn(54, C1499a.m614e0(C1499a.m585G(methodWriter, Opcodes.INVOKEVIRTUAL, JSONLexerBase, "scanInt", "(C)I"), fieldInfo.name, "_asm", context));
            } else {
                boolean z2 = z;
                int i6 = i3;
                if (cls3 == Byte.class) {
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitVarInsn(16, i4);
                    String str3 = JSONLexerBase;
                    methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str3, "scanInt", "(C)I");
                    methodWriter2.visitVarInsn(58, C1499a.m614e0(C1499a.m585G(methodWriter2, Opcodes.INVOKESTATIC, "java/lang/Byte", "valueOf", "(B)Ljava/lang/Byte;"), fieldInfo.name, "_asm", context));
                    Label label2 = new Label();
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitFieldInsn(180, str3, "matchStat", "I");
                    methodWriter2.visitLdcInsn(5);
                    methodWriter2.visitJumpInsn(Opcodes.IF_ICMPNE, label2);
                    methodWriter2.visitInsn(1);
                    methodWriter2.visitVarInsn(58, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
                    methodWriter2.visitLabel(label2);
                } else if (cls3 == Short.class) {
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitVarInsn(16, i4);
                    String str4 = JSONLexerBase;
                    methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str4, "scanInt", "(C)I");
                    methodWriter2.visitVarInsn(58, C1499a.m614e0(C1499a.m585G(methodWriter2, Opcodes.INVOKESTATIC, "java/lang/Short", "valueOf", "(S)Ljava/lang/Short;"), fieldInfo.name, "_asm", context));
                    Label label3 = new Label();
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitFieldInsn(180, str4, "matchStat", "I");
                    methodWriter2.visitLdcInsn(5);
                    methodWriter2.visitJumpInsn(Opcodes.IF_ICMPNE, label3);
                    methodWriter2.visitInsn(1);
                    methodWriter2.visitVarInsn(58, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
                    methodWriter2.visitLabel(label3);
                } else if (cls3 == Integer.class) {
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitVarInsn(16, i4);
                    String str5 = JSONLexerBase;
                    methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str5, "scanInt", "(C)I");
                    methodWriter2.visitVarInsn(58, C1499a.m614e0(C1499a.m585G(methodWriter2, Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;"), fieldInfo.name, "_asm", context));
                    Label label4 = new Label();
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitFieldInsn(180, str5, "matchStat", "I");
                    methodWriter2.visitLdcInsn(5);
                    methodWriter2.visitJumpInsn(Opcodes.IF_ICMPNE, label4);
                    methodWriter2.visitInsn(1);
                    methodWriter2.visitVarInsn(58, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
                    methodWriter2.visitLabel(label4);
                } else if (cls3 == Long.TYPE) {
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitVarInsn(16, i4);
                    StringBuilder m585G = C1499a.m585G(methodWriter2, Opcodes.INVOKEVIRTUAL, JSONLexerBase, "scanLong", "(C)J");
                    m585G.append(fieldInfo.name);
                    m585G.append("_asm");
                    methodWriter2.visitVarInsn(55, context.var(m585G.toString(), 2));
                } else if (cls3 == Long.class) {
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitVarInsn(16, i4);
                    String str6 = JSONLexerBase;
                    methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str6, "scanLong", "(C)J");
                    methodWriter2.visitVarInsn(58, C1499a.m614e0(C1499a.m585G(methodWriter2, Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;"), fieldInfo.name, "_asm", context));
                    Label label5 = new Label();
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitFieldInsn(180, str6, "matchStat", "I");
                    methodWriter2.visitLdcInsn(5);
                    methodWriter2.visitJumpInsn(Opcodes.IF_ICMPNE, label5);
                    methodWriter2.visitInsn(1);
                    methodWriter2.visitVarInsn(58, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
                    methodWriter2.visitLabel(label5);
                } else if (cls3 == Boolean.TYPE) {
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitVarInsn(16, i4);
                    methodWriter2.visitVarInsn(54, C1499a.m614e0(C1499a.m585G(methodWriter2, Opcodes.INVOKEVIRTUAL, JSONLexerBase, "scanBoolean", "(C)Z"), fieldInfo.name, "_asm", context));
                } else if (cls3 == Float.TYPE) {
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitVarInsn(16, i4);
                    methodWriter2.visitVarInsn(56, C1499a.m614e0(C1499a.m585G(methodWriter2, Opcodes.INVOKEVIRTUAL, JSONLexerBase, "scanFloat", "(C)F"), fieldInfo.name, "_asm", context));
                } else if (cls3 == Float.class) {
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitVarInsn(16, i4);
                    String str7 = JSONLexerBase;
                    methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str7, "scanFloat", "(C)F");
                    methodWriter2.visitVarInsn(58, C1499a.m614e0(C1499a.m585G(methodWriter2, Opcodes.INVOKESTATIC, "java/lang/Float", "valueOf", "(F)Ljava/lang/Float;"), fieldInfo.name, "_asm", context));
                    Label label6 = new Label();
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitFieldInsn(180, str7, "matchStat", "I");
                    methodWriter2.visitLdcInsn(5);
                    methodWriter2.visitJumpInsn(Opcodes.IF_ICMPNE, label6);
                    methodWriter2.visitInsn(1);
                    methodWriter2.visitVarInsn(58, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
                    methodWriter2.visitLabel(label6);
                } else if (cls3 == Double.TYPE) {
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitVarInsn(16, i4);
                    StringBuilder m585G2 = C1499a.m585G(methodWriter2, Opcodes.INVOKEVIRTUAL, JSONLexerBase, "scanDouble", "(C)D");
                    m585G2.append(fieldInfo.name);
                    m585G2.append("_asm");
                    methodWriter2.visitVarInsn(57, context.var(m585G2.toString(), 2));
                } else if (cls3 == Double.class) {
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitVarInsn(16, i4);
                    String str8 = JSONLexerBase;
                    methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str8, "scanDouble", "(C)D");
                    methodWriter2.visitVarInsn(58, C1499a.m614e0(C1499a.m585G(methodWriter2, Opcodes.INVOKESTATIC, "java/lang/Double", "valueOf", "(D)Ljava/lang/Double;"), fieldInfo.name, "_asm", context));
                    Label label7 = new Label();
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitFieldInsn(180, str8, "matchStat", "I");
                    methodWriter2.visitLdcInsn(5);
                    methodWriter2.visitJumpInsn(Opcodes.IF_ICMPNE, label7);
                    methodWriter2.visitInsn(1);
                    methodWriter2.visitVarInsn(58, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
                    methodWriter2.visitLabel(label7);
                } else if (cls3 == Character.TYPE) {
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitVarInsn(16, i4);
                    methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, JSONLexerBase, "scanString", "(C)Ljava/lang/String;");
                    methodWriter2.visitInsn(3);
                    methodWriter2.visitVarInsn(54, C1499a.m614e0(C1499a.m585G(methodWriter2, Opcodes.INVOKEVIRTUAL, "java/lang/String", "charAt", "(I)C"), fieldInfo.name, "_asm", context));
                } else if (cls3 == String.class) {
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitVarInsn(16, i4);
                    methodWriter2.visitVarInsn(58, C1499a.m614e0(C1499a.m585G(methodWriter2, Opcodes.INVOKEVIRTUAL, JSONLexerBase, "scanString", "(C)Ljava/lang/String;"), fieldInfo.name, "_asm", context));
                } else if (cls3 == BigDecimal.class) {
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitVarInsn(16, i4);
                    methodWriter2.visitVarInsn(58, C1499a.m614e0(C1499a.m585G(methodWriter2, Opcodes.INVOKEVIRTUAL, JSONLexerBase, "scanDecimal", "(C)Ljava/math/BigDecimal;"), fieldInfo.name, "_asm", context));
                } else if (cls3 == Date.class) {
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitVarInsn(16, i4);
                    methodWriter2.visitVarInsn(58, C1499a.m614e0(C1499a.m585G(methodWriter2, Opcodes.INVOKEVIRTUAL, JSONLexerBase, "scanDate", "(C)Ljava/util/Date;"), fieldInfo.name, "_asm", context));
                } else if (cls3 == UUID.class) {
                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                    methodWriter2.visitVarInsn(16, i4);
                    methodWriter2.visitVarInsn(58, C1499a.m614e0(C1499a.m585G(methodWriter2, Opcodes.INVOKEVIRTUAL, JSONLexerBase, "scanUUID", "(C)Ljava/util/UUID;"), fieldInfo.name, "_asm", context));
                } else {
                    if (cls3.isEnum()) {
                        Label label8 = new Label();
                        Label label9 = new Label();
                        Label label10 = new Label();
                        Label label11 = new Label();
                        cls = cls2;
                        methodWriter2.visitVarInsn(25, context.var("lexer"));
                        String str9 = JSONLexerBase;
                        methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str9, "getCurrent", "()C");
                        methodWriter2.visitInsn(89);
                        methodWriter2.visitVarInsn(54, context.var("ch"));
                        methodWriter2.visitLdcInsn(110);
                        methodWriter2.visitJumpInsn(Opcodes.IF_ICMPEQ, label11);
                        methodWriter2.visitVarInsn(21, context.var("ch"));
                        methodWriter2.visitLdcInsn(34);
                        methodWriter2.visitJumpInsn(Opcodes.IF_ICMPNE, label8);
                        methodWriter2.visitLabel(label11);
                        methodWriter2.visitVarInsn(25, context.var("lexer"));
                        methodWriter2.visitLdcInsn(Type.getType(ASMUtils.desc(cls3)));
                        methodWriter2.visitVarInsn(25, 1);
                        String str10 = DefaultJSONParser;
                        StringBuilder m586H4 = C1499a.m586H("()");
                        m586H4.append(ASMUtils.desc((Class<?>) SymbolTable.class));
                        methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str10, "getSymbolTable", m586H4.toString());
                        methodWriter2.visitVarInsn(16, i4);
                        methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str9, "scanEnum", "(Ljava/lang/Class;" + ASMUtils.desc((Class<?>) SymbolTable.class) + "C)Ljava/lang/Enum;");
                        methodWriter2.visitJumpInsn(Opcodes.GOTO, label10);
                        methodWriter2.visitLabel(label8);
                        methodWriter2.visitVarInsn(21, context.var("ch"));
                        methodWriter2.visitLdcInsn(48);
                        methodWriter2.visitJumpInsn(Opcodes.IF_ICMPLT, label9);
                        methodWriter2.visitVarInsn(21, context.var("ch"));
                        methodWriter2.visitLdcInsn(57);
                        methodWriter2.visitJumpInsn(Opcodes.IF_ICMPGT, label9);
                        _getFieldDeser(context, methodWriter2, fieldInfo);
                        methodWriter2.visitTypeInsn(Opcodes.CHECKCAST, ASMUtils.type(EnumDeserializer.class));
                        methodWriter2.visitVarInsn(25, context.var("lexer"));
                        methodWriter2.visitVarInsn(16, i4);
                        methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str9, "scanInt", "(C)I");
                        methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ASMUtils.type(EnumDeserializer.class), "valueOf", "(I)Ljava/lang/Enum;");
                        methodWriter2.visitJumpInsn(Opcodes.GOTO, label10);
                        methodWriter2.visitLabel(label9);
                        methodWriter2.visitVarInsn(25, 0);
                        methodWriter2.visitVarInsn(25, context.var("lexer"));
                        methodWriter2.visitVarInsn(16, i4);
                        methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ASMUtils.type(cls), "scanEnum", C1499a.m639y("(L", str9, ";C)Ljava/lang/Enum;"));
                        methodWriter2.visitLabel(label10);
                        methodWriter2.visitTypeInsn(Opcodes.CHECKCAST, ASMUtils.type(cls3));
                        methodWriter2.visitVarInsn(58, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
                    } else {
                        cls = cls2;
                        if (Collection.class.isAssignableFrom(cls3)) {
                            Class<?> collectionItemClass = TypeUtils.getCollectionItemClass(type2);
                            if (collectionItemClass == String.class) {
                                if (cls3 == List.class || cls3 == Collections.class || cls3 == ArrayList.class) {
                                    methodWriter2.visitTypeInsn(Opcodes.NEW, ASMUtils.type(ArrayList.class));
                                    methodWriter2.visitInsn(89);
                                    methodWriter2.visitMethodInsn(Opcodes.INVOKESPECIAL, ASMUtils.type(ArrayList.class), "<init>", "()V");
                                } else {
                                    methodWriter2.visitLdcInsn(Type.getType(ASMUtils.desc(cls3)));
                                    methodWriter2.visitMethodInsn(Opcodes.INVOKESTATIC, ASMUtils.type(TypeUtils.class), "createCollection", "(Ljava/lang/Class;)Ljava/util/Collection;");
                                }
                                methodWriter2.visitVarInsn(58, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
                                methodWriter2.visitVarInsn(25, context.var("lexer"));
                                methodWriter2.visitVarInsn(25, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
                                methodWriter2.visitVarInsn(16, i4);
                                String str11 = JSONLexerBase;
                                methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str11, "scanStringArray", "(Ljava/util/Collection;C)V");
                                Label label12 = new Label();
                                methodWriter2.visitVarInsn(25, context.var("lexer"));
                                methodWriter2.visitFieldInsn(180, str11, "matchStat", "I");
                                methodWriter2.visitLdcInsn(5);
                                methodWriter2.visitJumpInsn(Opcodes.IF_ICMPNE, label12);
                                methodWriter2.visitInsn(1);
                                methodWriter2.visitVarInsn(58, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
                                methodWriter2.visitLabel(label12);
                            } else {
                                Label label13 = new Label();
                                methodWriter2.visitVarInsn(25, context.var("lexer"));
                                String str12 = JSONLexerBase;
                                methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str12, "token", "()I");
                                methodWriter2.visitVarInsn(54, context.var("token"));
                                methodWriter2.visitVarInsn(21, context.var("token"));
                                int i7 = i6 == 0 ? 14 : 16;
                                methodWriter2.visitLdcInsn(Integer.valueOf(i7));
                                methodWriter2.visitJumpInsn(Opcodes.IF_ICMPEQ, label13);
                                methodWriter2.visitVarInsn(25, 1);
                                methodWriter2.visitLdcInsn(Integer.valueOf(i7));
                                String str13 = DefaultJSONParser;
                                methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str13, "throwException", "(I)V");
                                methodWriter2.visitLabel(label13);
                                Label label14 = new Label();
                                Label label15 = new Label();
                                methodWriter2.visitVarInsn(25, context.var("lexer"));
                                methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str12, "getCurrent", "()C");
                                methodWriter2.visitVarInsn(16, 91);
                                methodWriter2.visitJumpInsn(Opcodes.IF_ICMPNE, label14);
                                methodWriter2.visitVarInsn(25, context.var("lexer"));
                                methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str12, "next", "()C");
                                methodWriter2.visitInsn(87);
                                methodWriter2.visitVarInsn(25, context.var("lexer"));
                                methodWriter2.visitLdcInsn(14);
                                methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str12, "setToken", "(I)V");
                                methodWriter2.visitJumpInsn(Opcodes.GOTO, label15);
                                methodWriter2.visitLabel(label14);
                                methodWriter2.visitVarInsn(25, context.var("lexer"));
                                methodWriter2.visitLdcInsn(14);
                                methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str12, "nextToken", "(I)V");
                                methodWriter2.visitLabel(label15);
                                i2 = i6;
                                _newCollection(methodWriter2, cls3, i2, false);
                                methodWriter2.visitInsn(89);
                                methodWriter2.visitVarInsn(58, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
                                _getCollectionFieldItemDeser(context, methodWriter2, fieldInfo, collectionItemClass);
                                methodWriter2.visitVarInsn(25, 1);
                                methodWriter2.visitLdcInsn(Type.getType(ASMUtils.desc(collectionItemClass)));
                                methodWriter2.visitVarInsn(25, 3);
                                String type3 = ASMUtils.type(cls);
                                StringBuilder m586H5 = C1499a.m586H("(Ljava/util/Collection;");
                                m586H5.append(ASMUtils.desc((Class<?>) ObjectDeserializer.class));
                                m586H5.append("L");
                                m586H5.append(str13);
                                m586H5.append(";Ljava/lang/reflect/Type;Ljava/lang/Object;)V");
                                methodWriter2.visitMethodInsn(Opcodes.INVOKESTATIC, type3, "parseArray", m586H5.toString());
                            }
                        } else {
                            i2 = i6;
                            if (cls3.isArray()) {
                                methodWriter2.visitVarInsn(25, context.var("lexer"));
                                methodWriter2.visitLdcInsn(14);
                                methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, JSONLexerBase, "nextToken", "(I)V");
                                methodWriter2.visitVarInsn(25, 1);
                                methodWriter2.visitVarInsn(25, 0);
                                methodWriter2.visitLdcInsn(Integer.valueOf(i2));
                                methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ASMUtils.type(cls), "getFieldType", "(I)Ljava/lang/reflect/Type;");
                                methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, DefaultJSONParser, "parseObject", "(Ljava/lang/reflect/Type;)Ljava/lang/Object;");
                                methodWriter2.visitTypeInsn(Opcodes.CHECKCAST, ASMUtils.type(cls3));
                                methodWriter2.visitVarInsn(58, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
                            } else {
                                Label label16 = new Label();
                                Label label17 = new Label();
                                if (cls3 == Date.class) {
                                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                                    String str14 = JSONLexerBase;
                                    methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str14, "getCurrent", "()C");
                                    methodWriter2.visitLdcInsn(49);
                                    methodWriter2.visitJumpInsn(Opcodes.IF_ICMPNE, label16);
                                    methodWriter2.visitTypeInsn(Opcodes.NEW, ASMUtils.type(Date.class));
                                    methodWriter2.visitInsn(89);
                                    methodWriter2.visitVarInsn(25, context.var("lexer"));
                                    methodWriter2.visitVarInsn(16, i4);
                                    methodWriter2.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str14, "scanLong", "(C)J");
                                    methodWriter2.visitMethodInsn(Opcodes.INVOKESPECIAL, ASMUtils.type(Date.class), "<init>", "(J)V");
                                    methodWriter2.visitVarInsn(58, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
                                    methodWriter2.visitJumpInsn(Opcodes.GOTO, label17);
                                }
                                methodWriter2.visitLabel(label16);
                                _quickNextToken(context, methodWriter2, 14);
                                methodWriter = methodWriter2;
                                _deserObject(context, methodWriter2, fieldInfo, cls3, i2);
                                methodWriter.visitVarInsn(25, context.var("lexer"));
                                methodWriter.visitMethodInsn(Opcodes.INVOKEVIRTUAL, JSONLexerBase, "token", "()I");
                                methodWriter.visitLdcInsn(15);
                                methodWriter.visitJumpInsn(Opcodes.IF_ICMPEQ, label17);
                                methodWriter.visitVarInsn(25, 0);
                                methodWriter.visitVarInsn(25, context.var("lexer"));
                                if (z2) {
                                    methodWriter.visitLdcInsn(15);
                                } else {
                                    methodWriter.visitLdcInsn(16);
                                }
                                String type4 = ASMUtils.type(cls);
                                StringBuilder m586H6 = C1499a.m586H(ChineseToPinyinResource.Field.LEFT_BRACKET);
                                m586H6.append(ASMUtils.desc((Class<?>) JSONLexer.class));
                                m586H6.append("I)V");
                                methodWriter.visitMethodInsn(Opcodes.INVOKESPECIAL, type4, "check", m586H6.toString());
                                methodWriter.visitLabel(label17);
                            }
                        }
                        methodWriter = methodWriter2;
                    }
                    i2 = i6;
                    methodWriter = methodWriter2;
                }
                cls = cls2;
                i2 = i6;
                methodWriter = methodWriter2;
            }
            int i8 = i2 + 1;
            fieldInfoArr = fieldInfoArr2;
            methodWriter2 = methodWriter;
            length = i5;
            cls2 = cls;
            i3 = i8;
        }
        MethodVisitor methodVisitor = methodWriter2;
        _batchSet(context, methodVisitor, false);
        Label label18 = new Label();
        Label label19 = new Label();
        Label label20 = new Label();
        Label label21 = new Label();
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        String str15 = JSONLexerBase;
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str15, "getCurrent", "()C");
        methodVisitor.visitInsn(89);
        methodVisitor.visitVarInsn(54, context.var("ch"));
        methodVisitor.visitVarInsn(16, 44);
        methodVisitor.visitJumpInsn(Opcodes.IF_ICMPNE, label19);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str15, "next", "()C");
        methodVisitor.visitInsn(87);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitLdcInsn(16);
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str15, "setToken", "(I)V");
        methodVisitor.visitJumpInsn(Opcodes.GOTO, label21);
        methodVisitor.visitLabel(label19);
        methodVisitor.visitVarInsn(21, context.var("ch"));
        methodVisitor.visitVarInsn(16, 93);
        methodVisitor.visitJumpInsn(Opcodes.IF_ICMPNE, label20);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str15, "next", "()C");
        methodVisitor.visitInsn(87);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitLdcInsn(15);
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str15, "setToken", "(I)V");
        methodVisitor.visitJumpInsn(Opcodes.GOTO, label21);
        methodVisitor.visitLabel(label20);
        methodVisitor.visitVarInsn(21, context.var("ch"));
        methodVisitor.visitVarInsn(16, 26);
        methodVisitor.visitJumpInsn(Opcodes.IF_ICMPNE, label18);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str15, "next", "()C");
        methodVisitor.visitInsn(87);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitLdcInsn(20);
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str15, "setToken", "(I)V");
        methodVisitor.visitJumpInsn(Opcodes.GOTO, label21);
        methodVisitor.visitLabel(label18);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitLdcInsn(16);
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str15, "nextToken", "(I)V");
        methodVisitor.visitLabel(label21);
        methodVisitor.visitVarInsn(25, context.var("instance"));
        methodVisitor.visitInsn(Opcodes.ARETURN);
        methodVisitor.visitMaxs(5, context.variantIndex);
        methodVisitor.visitEnd();
    }

    private void _deserialze_list_obj(Context context, MethodVisitor methodVisitor, Label label, FieldInfo fieldInfo, Class<?> cls, Class<?> cls2, int i2) {
        String str;
        String str2;
        String str3;
        String str4;
        Label label2;
        int i3;
        Label label3 = new Label();
        String str5 = JSONLexerBase;
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str5, "matchField", "([C)Z");
        methodVisitor.visitJumpInsn(Opcodes.IFEQ, label3);
        _setFlag(methodVisitor, context, i2);
        Label label4 = new Label();
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str5, "token", "()I");
        methodVisitor.visitLdcInsn(8);
        methodVisitor.visitJumpInsn(Opcodes.IF_ICMPNE, label4);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitLdcInsn(16);
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str5, "nextToken", "(I)V");
        methodVisitor.visitJumpInsn(Opcodes.GOTO, label3);
        methodVisitor.visitLabel(label4);
        Label label5 = new Label();
        Label label6 = new Label();
        Label label7 = new Label();
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str5, "token", "()I");
        methodVisitor.visitLdcInsn(21);
        methodVisitor.visitJumpInsn(Opcodes.IF_ICMPNE, label6);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitLdcInsn(14);
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str5, "nextToken", "(I)V");
        _newCollection(methodVisitor, cls, i2, true);
        methodVisitor.visitJumpInsn(Opcodes.GOTO, label5);
        methodVisitor.visitLabel(label6);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str5, "token", "()I");
        methodVisitor.visitLdcInsn(14);
        methodVisitor.visitJumpInsn(Opcodes.IF_ICMPEQ, label7);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str5, "token", "()I");
        methodVisitor.visitLdcInsn(12);
        methodVisitor.visitJumpInsn(Opcodes.IF_ICMPNE, label);
        _newCollection(methodVisitor, cls, i2, false);
        methodVisitor.visitVarInsn(58, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
        _getCollectionFieldItemDeser(context, methodVisitor, fieldInfo, cls2);
        methodVisitor.visitVarInsn(25, 1);
        methodVisitor.visitLdcInsn(Type.getType(ASMUtils.desc(cls2)));
        methodVisitor.visitInsn(3);
        methodVisitor.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;");
        String type = ASMUtils.type(ObjectDeserializer.class);
        StringBuilder m586H = C1499a.m586H("(L");
        String str6 = DefaultJSONParser;
        methodVisitor.visitMethodInsn(Opcodes.INVOKEINTERFACE, type, "deserialze", C1499a.m582D(m586H, str6, ";Ljava/lang/reflect/Type;Ljava/lang/Object;)Ljava/lang/Object;"));
        methodVisitor.visitVarInsn(58, context.var("list_item_value"));
        methodVisitor.visitVarInsn(25, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
        methodVisitor.visitVarInsn(25, context.var("list_item_value"));
        if (cls.isInterface()) {
            str = "list_item_value";
            methodVisitor.visitMethodInsn(Opcodes.INVOKEINTERFACE, ASMUtils.type(cls), "add", "(Ljava/lang/Object;)Z");
        } else {
            str = "list_item_value";
            methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ASMUtils.type(cls), "add", "(Ljava/lang/Object;)Z");
        }
        methodVisitor.visitInsn(87);
        methodVisitor.visitJumpInsn(Opcodes.GOTO, label3);
        methodVisitor.visitLabel(label7);
        _newCollection(methodVisitor, cls, i2, false);
        methodVisitor.visitLabel(label5);
        methodVisitor.visitVarInsn(58, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
        boolean isPrimitive2 = ParserConfig.isPrimitive2(fieldInfo.fieldClass);
        _getCollectionFieldItemDeser(context, methodVisitor, fieldInfo, cls2);
        if (isPrimitive2) {
            methodVisitor.visitMethodInsn(Opcodes.INVOKEINTERFACE, ASMUtils.type(ObjectDeserializer.class), "getFastMatchToken", "()I");
            methodVisitor.visitVarInsn(54, context.var("fastMatchToken"));
            methodVisitor.visitVarInsn(25, context.var("lexer"));
            methodVisitor.visitVarInsn(21, context.var("fastMatchToken"));
            str2 = "nextToken";
            str3 = str5;
            str4 = "(I)V";
            methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str3, str2, str4);
            label2 = label3;
        } else {
            str2 = "nextToken";
            str3 = str5;
            str4 = "(I)V";
            methodVisitor.visitInsn(87);
            methodVisitor.visitLdcInsn(12);
            label2 = label3;
            methodVisitor.visitVarInsn(54, context.var("fastMatchToken"));
            _quickNextToken(context, methodVisitor, 12);
        }
        methodVisitor.visitVarInsn(25, 1);
        String str7 = str4;
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str6, "getContext", "()" + ASMUtils.desc((Class<?>) ParseContext.class));
        methodVisitor.visitVarInsn(58, context.var("listContext"));
        methodVisitor.visitVarInsn(25, 1);
        methodVisitor.visitVarInsn(25, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
        methodVisitor.visitLdcInsn(fieldInfo.name);
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str6, "setContext", "(Ljava/lang/Object;Ljava/lang/Object;)" + ASMUtils.desc((Class<?>) ParseContext.class));
        methodVisitor.visitInsn(87);
        Label label8 = new Label();
        Label label9 = new Label();
        methodVisitor.visitInsn(3);
        String str8 = str2;
        methodVisitor.visitVarInsn(54, context.var("i"));
        methodVisitor.visitLabel(label8);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str3, "token", "()I");
        methodVisitor.visitLdcInsn(15);
        methodVisitor.visitJumpInsn(Opcodes.IF_ICMPEQ, label9);
        methodVisitor.visitVarInsn(25, 0);
        methodVisitor.visitFieldInsn(180, context.className, C1499a.m582D(new StringBuilder(), fieldInfo.name, "_asm_list_item_deser__"), ASMUtils.desc((Class<?>) ObjectDeserializer.class));
        methodVisitor.visitVarInsn(25, 1);
        methodVisitor.visitLdcInsn(Type.getType(ASMUtils.desc(cls2)));
        methodVisitor.visitVarInsn(21, context.var("i"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;");
        methodVisitor.visitMethodInsn(Opcodes.INVOKEINTERFACE, ASMUtils.type(ObjectDeserializer.class), "deserialze", C1499a.m639y("(L", str6, ";Ljava/lang/reflect/Type;Ljava/lang/Object;)Ljava/lang/Object;"));
        String str9 = str;
        methodVisitor.visitVarInsn(58, context.var(str9));
        methodVisitor.visitIincInsn(context.var("i"), 1);
        methodVisitor.visitVarInsn(25, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
        methodVisitor.visitVarInsn(25, context.var(str9));
        if (cls.isInterface()) {
            methodVisitor.visitMethodInsn(Opcodes.INVOKEINTERFACE, ASMUtils.type(cls), "add", "(Ljava/lang/Object;)Z");
        } else {
            methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ASMUtils.type(cls), "add", "(Ljava/lang/Object;)Z");
        }
        methodVisitor.visitInsn(87);
        methodVisitor.visitVarInsn(25, 1);
        methodVisitor.visitVarInsn(25, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str6, "checkListResolve", "(Ljava/util/Collection;)V");
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str3, "token", "()I");
        methodVisitor.visitLdcInsn(16);
        methodVisitor.visitJumpInsn(Opcodes.IF_ICMPNE, label8);
        if (isPrimitive2) {
            methodVisitor.visitVarInsn(25, context.var("lexer"));
            methodVisitor.visitVarInsn(21, context.var("fastMatchToken"));
            methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str3, str8, str7);
            i3 = Opcodes.GOTO;
        } else {
            _quickNextToken(context, methodVisitor, 12);
            i3 = Opcodes.GOTO;
        }
        methodVisitor.visitJumpInsn(i3, label8);
        methodVisitor.visitLabel(label9);
        methodVisitor.visitVarInsn(25, 1);
        methodVisitor.visitVarInsn(25, context.var("listContext"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str6, "setContext", ChineseToPinyinResource.Field.LEFT_BRACKET + ASMUtils.desc((Class<?>) ParseContext.class) + ")V");
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str3, "token", "()I");
        methodVisitor.visitLdcInsn(15);
        methodVisitor.visitJumpInsn(Opcodes.IF_ICMPNE, label);
        _quickNextTokenComma(context, methodVisitor);
        methodVisitor.visitLabel(label2);
    }

    private void _deserialze_obj(Context context, MethodVisitor methodVisitor, Label label, FieldInfo fieldInfo, Class<?> cls, int i2) {
        Label label2 = new Label();
        Label label3 = new Label();
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitVarInsn(25, 0);
        methodVisitor.visitFieldInsn(180, context.className, C1499a.m582D(new StringBuilder(), fieldInfo.name, "_asm_prefix__"), "[C");
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, JSONLexerBase, "matchField", "([C)Z");
        methodVisitor.visitJumpInsn(Opcodes.IFNE, label2);
        methodVisitor.visitInsn(1);
        methodVisitor.visitVarInsn(58, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
        methodVisitor.visitJumpInsn(Opcodes.GOTO, label3);
        methodVisitor.visitLabel(label2);
        _setFlag(methodVisitor, context, i2);
        methodVisitor.visitVarInsn(21, context.var("matchedCount"));
        methodVisitor.visitInsn(4);
        methodVisitor.visitInsn(96);
        methodVisitor.visitVarInsn(54, context.var("matchedCount"));
        _deserObject(context, methodVisitor, fieldInfo, cls, i2);
        methodVisitor.visitVarInsn(25, 1);
        String str = DefaultJSONParser;
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "getResolveStatus", "()I");
        methodVisitor.visitLdcInsn(1);
        methodVisitor.visitJumpInsn(Opcodes.IF_ICMPNE, label3);
        methodVisitor.visitVarInsn(25, 1);
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "getLastResolveTask", "()" + ASMUtils.desc((Class<?>) DefaultJSONParser.ResolveTask.class));
        methodVisitor.visitVarInsn(58, context.var("resolveTask"));
        methodVisitor.visitVarInsn(25, context.var("resolveTask"));
        methodVisitor.visitVarInsn(25, 1);
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "getContext", "()" + ASMUtils.desc((Class<?>) ParseContext.class));
        methodVisitor.visitFieldInsn(Opcodes.PUTFIELD, ASMUtils.type(DefaultJSONParser.ResolveTask.class), "ownerContext", ASMUtils.desc((Class<?>) ParseContext.class));
        methodVisitor.visitVarInsn(25, context.var("resolveTask"));
        methodVisitor.visitVarInsn(25, 0);
        methodVisitor.visitLdcInsn(fieldInfo.name);
        String type = ASMUtils.type(JavaBeanDeserializer.class);
        StringBuilder m586H = C1499a.m586H("(Ljava/lang/String;)");
        m586H.append(ASMUtils.desc((Class<?>) FieldDeserializer.class));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, type, "getFieldDeserializer", m586H.toString());
        methodVisitor.visitFieldInsn(Opcodes.PUTFIELD, ASMUtils.type(DefaultJSONParser.ResolveTask.class), "fieldDeserializer", ASMUtils.desc((Class<?>) FieldDeserializer.class));
        methodVisitor.visitVarInsn(25, 1);
        methodVisitor.visitLdcInsn(0);
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "setResolveStatus", "(I)V");
        methodVisitor.visitLabel(label3);
    }

    private void _getCollectionFieldItemDeser(Context context, MethodVisitor methodVisitor, FieldInfo fieldInfo, Class<?> cls) {
        Label label = new Label();
        methodVisitor.visitVarInsn(25, 0);
        methodVisitor.visitFieldInsn(180, context.className, C1499a.m582D(new StringBuilder(), fieldInfo.name, "_asm_list_item_deser__"), ASMUtils.desc((Class<?>) ObjectDeserializer.class));
        methodVisitor.visitJumpInsn(Opcodes.IFNONNULL, label);
        methodVisitor.visitVarInsn(25, 0);
        methodVisitor.visitVarInsn(25, 1);
        String str = DefaultJSONParser;
        StringBuilder m586H = C1499a.m586H("()");
        m586H.append(ASMUtils.desc((Class<?>) ParserConfig.class));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "getConfig", m586H.toString());
        methodVisitor.visitLdcInsn(Type.getType(ASMUtils.desc(cls)));
        String type = ASMUtils.type(ParserConfig.class);
        StringBuilder m586H2 = C1499a.m586H("(Ljava/lang/reflect/Type;)");
        m586H2.append(ASMUtils.desc((Class<?>) ObjectDeserializer.class));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, type, "getDeserializer", m586H2.toString());
        methodVisitor.visitFieldInsn(Opcodes.PUTFIELD, context.className, C1499a.m582D(new StringBuilder(), fieldInfo.name, "_asm_list_item_deser__"), ASMUtils.desc((Class<?>) ObjectDeserializer.class));
        methodVisitor.visitLabel(label);
        methodVisitor.visitVarInsn(25, 0);
        methodVisitor.visitFieldInsn(180, context.className, C1499a.m582D(new StringBuilder(), fieldInfo.name, "_asm_list_item_deser__"), ASMUtils.desc((Class<?>) ObjectDeserializer.class));
    }

    private void _getFieldDeser(Context context, MethodVisitor methodVisitor, FieldInfo fieldInfo) {
        Label label = new Label();
        methodVisitor.visitVarInsn(25, 0);
        methodVisitor.visitFieldInsn(180, context.className, C1499a.m582D(new StringBuilder(), fieldInfo.name, "_asm_deser__"), ASMUtils.desc((Class<?>) ObjectDeserializer.class));
        methodVisitor.visitJumpInsn(Opcodes.IFNONNULL, label);
        methodVisitor.visitVarInsn(25, 0);
        methodVisitor.visitVarInsn(25, 1);
        String str = DefaultJSONParser;
        StringBuilder m586H = C1499a.m586H("()");
        m586H.append(ASMUtils.desc((Class<?>) ParserConfig.class));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "getConfig", m586H.toString());
        methodVisitor.visitLdcInsn(Type.getType(ASMUtils.desc(fieldInfo.fieldClass)));
        String type = ASMUtils.type(ParserConfig.class);
        StringBuilder m586H2 = C1499a.m586H("(Ljava/lang/reflect/Type;)");
        m586H2.append(ASMUtils.desc((Class<?>) ObjectDeserializer.class));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, type, "getDeserializer", m586H2.toString());
        methodVisitor.visitFieldInsn(Opcodes.PUTFIELD, context.className, C1499a.m582D(new StringBuilder(), fieldInfo.name, "_asm_deser__"), ASMUtils.desc((Class<?>) ObjectDeserializer.class));
        methodVisitor.visitLabel(label);
        methodVisitor.visitVarInsn(25, 0);
        methodVisitor.visitFieldInsn(180, context.className, C1499a.m582D(new StringBuilder(), fieldInfo.name, "_asm_deser__"), ASMUtils.desc((Class<?>) ObjectDeserializer.class));
    }

    private void _init(ClassWriter classWriter, Context context) {
        int length = context.fieldInfoList.length;
        for (int i2 = 0; i2 < length; i2++) {
            new FieldWriter(classWriter, 1, C1499a.m582D(new StringBuilder(), context.fieldInfoList[i2].name, "_asm_prefix__"), "[C").visitEnd();
        }
        int length2 = context.fieldInfoList.length;
        for (int i3 = 0; i3 < length2; i3++) {
            FieldInfo fieldInfo = context.fieldInfoList[i3];
            Class<?> cls = fieldInfo.fieldClass;
            if (!cls.isPrimitive()) {
                if (Collection.class.isAssignableFrom(cls)) {
                    new FieldWriter(classWriter, 1, C1499a.m582D(new StringBuilder(), fieldInfo.name, "_asm_list_item_deser__"), ASMUtils.desc((Class<?>) ObjectDeserializer.class)).visitEnd();
                } else {
                    new FieldWriter(classWriter, 1, C1499a.m582D(new StringBuilder(), fieldInfo.name, "_asm_deser__"), ASMUtils.desc((Class<?>) ObjectDeserializer.class)).visitEnd();
                }
            }
        }
        StringBuilder m586H = C1499a.m586H(ChineseToPinyinResource.Field.LEFT_BRACKET);
        m586H.append(ASMUtils.desc((Class<?>) ParserConfig.class));
        m586H.append(ASMUtils.desc((Class<?>) JavaBeanInfo.class));
        m586H.append(")V");
        MethodWriter methodWriter = new MethodWriter(classWriter, 1, "<init>", m586H.toString(), null, null);
        methodWriter.visitVarInsn(25, 0);
        methodWriter.visitVarInsn(25, 1);
        methodWriter.visitVarInsn(25, 2);
        String type = ASMUtils.type(JavaBeanDeserializer.class);
        StringBuilder m586H2 = C1499a.m586H(ChineseToPinyinResource.Field.LEFT_BRACKET);
        m586H2.append(ASMUtils.desc((Class<?>) ParserConfig.class));
        m586H2.append(ASMUtils.desc((Class<?>) JavaBeanInfo.class));
        m586H2.append(")V");
        methodWriter.visitMethodInsn(Opcodes.INVOKESPECIAL, type, "<init>", m586H2.toString());
        int length3 = context.fieldInfoList.length;
        for (int i4 = 0; i4 < length3; i4++) {
            FieldInfo fieldInfo2 = context.fieldInfoList[i4];
            methodWriter.visitVarInsn(25, 0);
            methodWriter.visitLdcInsn("\"" + fieldInfo2.name + "\":");
            methodWriter.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "toCharArray", "()[C");
            methodWriter.visitFieldInsn(Opcodes.PUTFIELD, context.className, C1499a.m582D(new StringBuilder(), fieldInfo2.name, "_asm_prefix__"), "[C");
        }
        methodWriter.visitInsn(Opcodes.RETURN);
        methodWriter.visitMaxs(4, 4);
        methodWriter.visitEnd();
    }

    private void _isFlag(MethodVisitor methodVisitor, Context context, int i2, Label label) {
        StringBuilder m586H = C1499a.m586H("_asm_flag_");
        m586H.append(i2 / 32);
        methodVisitor.visitVarInsn(21, context.var(m586H.toString()));
        methodVisitor.visitLdcInsn(Integer.valueOf(1 << i2));
        methodVisitor.visitInsn(126);
        methodVisitor.visitJumpInsn(Opcodes.IFEQ, label);
    }

    private void _loadAndSet(Context context, MethodVisitor methodVisitor, FieldInfo fieldInfo) {
        Class<?> cls = fieldInfo.fieldClass;
        java.lang.reflect.Type type = fieldInfo.fieldType;
        if (cls == Boolean.TYPE) {
            methodVisitor.visitVarInsn(25, context.var("instance"));
            methodVisitor.visitVarInsn(21, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
            _set(context, methodVisitor, fieldInfo);
            return;
        }
        if (cls == Byte.TYPE || cls == Short.TYPE || cls == Integer.TYPE || cls == Character.TYPE) {
            methodVisitor.visitVarInsn(25, context.var("instance"));
            methodVisitor.visitVarInsn(21, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
            _set(context, methodVisitor, fieldInfo);
            return;
        }
        if (cls == Long.TYPE) {
            methodVisitor.visitVarInsn(25, context.var("instance"));
            methodVisitor.visitVarInsn(22, context.var(fieldInfo.name + "_asm", 2));
            if (fieldInfo.method == null) {
                methodVisitor.visitFieldInsn(Opcodes.PUTFIELD, ASMUtils.type(fieldInfo.declaringClass), fieldInfo.field.getName(), ASMUtils.desc(fieldInfo.fieldClass));
                return;
            }
            methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ASMUtils.type(context.getInstClass()), fieldInfo.method.getName(), ASMUtils.desc(fieldInfo.method));
            if (fieldInfo.method.getReturnType().equals(Void.TYPE)) {
                return;
            }
            methodVisitor.visitInsn(87);
            return;
        }
        if (cls == Float.TYPE) {
            methodVisitor.visitVarInsn(25, context.var("instance"));
            methodVisitor.visitVarInsn(23, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
            _set(context, methodVisitor, fieldInfo);
            return;
        }
        if (cls == Double.TYPE) {
            methodVisitor.visitVarInsn(25, context.var("instance"));
            methodVisitor.visitVarInsn(24, context.var(fieldInfo.name + "_asm", 2));
            _set(context, methodVisitor, fieldInfo);
            return;
        }
        if (cls == String.class) {
            methodVisitor.visitVarInsn(25, context.var("instance"));
            methodVisitor.visitVarInsn(25, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
            _set(context, methodVisitor, fieldInfo);
            return;
        }
        if (cls.isEnum()) {
            methodVisitor.visitVarInsn(25, context.var("instance"));
            methodVisitor.visitVarInsn(25, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
            _set(context, methodVisitor, fieldInfo);
        } else if (!Collection.class.isAssignableFrom(cls)) {
            methodVisitor.visitVarInsn(25, context.var("instance"));
            methodVisitor.visitVarInsn(25, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
            _set(context, methodVisitor, fieldInfo);
        } else {
            methodVisitor.visitVarInsn(25, context.var("instance"));
            if (TypeUtils.getCollectionItemClass(type) == String.class) {
                methodVisitor.visitVarInsn(25, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
                methodVisitor.visitTypeInsn(Opcodes.CHECKCAST, ASMUtils.type(cls));
            } else {
                methodVisitor.visitVarInsn(25, C1499a.m614e0(new StringBuilder(), fieldInfo.name, "_asm", context));
            }
            _set(context, methodVisitor, fieldInfo);
        }
    }

    private void _newCollection(MethodVisitor methodVisitor, Class<?> cls, int i2, boolean z) {
        if (cls.isAssignableFrom(ArrayList.class) && !z) {
            methodVisitor.visitTypeInsn(Opcodes.NEW, "java/util/ArrayList");
            methodVisitor.visitInsn(89);
            methodVisitor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/util/ArrayList", "<init>", "()V");
        } else if (cls.isAssignableFrom(LinkedList.class) && !z) {
            methodVisitor.visitTypeInsn(Opcodes.NEW, ASMUtils.type(LinkedList.class));
            methodVisitor.visitInsn(89);
            methodVisitor.visitMethodInsn(Opcodes.INVOKESPECIAL, ASMUtils.type(LinkedList.class), "<init>", "()V");
        } else if (cls.isAssignableFrom(HashSet.class)) {
            methodVisitor.visitTypeInsn(Opcodes.NEW, ASMUtils.type(HashSet.class));
            methodVisitor.visitInsn(89);
            methodVisitor.visitMethodInsn(Opcodes.INVOKESPECIAL, ASMUtils.type(HashSet.class), "<init>", "()V");
        } else if (cls.isAssignableFrom(TreeSet.class)) {
            methodVisitor.visitTypeInsn(Opcodes.NEW, ASMUtils.type(TreeSet.class));
            methodVisitor.visitInsn(89);
            methodVisitor.visitMethodInsn(Opcodes.INVOKESPECIAL, ASMUtils.type(TreeSet.class), "<init>", "()V");
        } else if (cls.isAssignableFrom(LinkedHashSet.class)) {
            methodVisitor.visitTypeInsn(Opcodes.NEW, ASMUtils.type(LinkedHashSet.class));
            methodVisitor.visitInsn(89);
            methodVisitor.visitMethodInsn(Opcodes.INVOKESPECIAL, ASMUtils.type(LinkedHashSet.class), "<init>", "()V");
        } else if (z) {
            methodVisitor.visitTypeInsn(Opcodes.NEW, ASMUtils.type(HashSet.class));
            methodVisitor.visitInsn(89);
            methodVisitor.visitMethodInsn(Opcodes.INVOKESPECIAL, ASMUtils.type(HashSet.class), "<init>", "()V");
        } else {
            methodVisitor.visitVarInsn(25, 0);
            methodVisitor.visitLdcInsn(Integer.valueOf(i2));
            methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ASMUtils.type(JavaBeanDeserializer.class), "getFieldType", "(I)Ljava/lang/reflect/Type;");
            methodVisitor.visitMethodInsn(Opcodes.INVOKESTATIC, ASMUtils.type(TypeUtils.class), "createCollection", "(Ljava/lang/reflect/Type;)Ljava/util/Collection;");
        }
        methodVisitor.visitTypeInsn(Opcodes.CHECKCAST, ASMUtils.type(cls));
    }

    private void _quickNextToken(Context context, MethodVisitor methodVisitor, int i2) {
        Label label = new Label();
        Label label2 = new Label();
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        String str = JSONLexerBase;
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "getCurrent", "()C");
        if (i2 == 12) {
            methodVisitor.visitVarInsn(16, 123);
        } else {
            if (i2 != 14) {
                throw new IllegalStateException();
            }
            methodVisitor.visitVarInsn(16, 91);
        }
        methodVisitor.visitJumpInsn(Opcodes.IF_ICMPNE, label);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "next", "()C");
        methodVisitor.visitInsn(87);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitLdcInsn(Integer.valueOf(i2));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "setToken", "(I)V");
        methodVisitor.visitJumpInsn(Opcodes.GOTO, label2);
        methodVisitor.visitLabel(label);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitLdcInsn(Integer.valueOf(i2));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "nextToken", "(I)V");
        methodVisitor.visitLabel(label2);
    }

    private void _quickNextTokenComma(Context context, MethodVisitor methodVisitor) {
        Label label = new Label();
        Label label2 = new Label();
        Label label3 = new Label();
        Label label4 = new Label();
        Label label5 = new Label();
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        String str = JSONLexerBase;
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "getCurrent", "()C");
        methodVisitor.visitInsn(89);
        methodVisitor.visitVarInsn(54, context.var("ch"));
        methodVisitor.visitVarInsn(16, 44);
        methodVisitor.visitJumpInsn(Opcodes.IF_ICMPNE, label2);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "next", "()C");
        methodVisitor.visitInsn(87);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitLdcInsn(16);
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "setToken", "(I)V");
        methodVisitor.visitJumpInsn(Opcodes.GOTO, label5);
        methodVisitor.visitLabel(label2);
        methodVisitor.visitVarInsn(21, context.var("ch"));
        methodVisitor.visitVarInsn(16, 125);
        methodVisitor.visitJumpInsn(Opcodes.IF_ICMPNE, label3);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "next", "()C");
        methodVisitor.visitInsn(87);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitLdcInsn(13);
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "setToken", "(I)V");
        methodVisitor.visitJumpInsn(Opcodes.GOTO, label5);
        methodVisitor.visitLabel(label3);
        methodVisitor.visitVarInsn(21, context.var("ch"));
        methodVisitor.visitVarInsn(16, 93);
        methodVisitor.visitJumpInsn(Opcodes.IF_ICMPNE, label4);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "next", "()C");
        methodVisitor.visitInsn(87);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitLdcInsn(15);
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "setToken", "(I)V");
        methodVisitor.visitJumpInsn(Opcodes.GOTO, label5);
        methodVisitor.visitLabel(label4);
        methodVisitor.visitVarInsn(21, context.var("ch"));
        methodVisitor.visitVarInsn(16, 26);
        methodVisitor.visitJumpInsn(Opcodes.IF_ICMPNE, label);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitLdcInsn(20);
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "setToken", "(I)V");
        methodVisitor.visitJumpInsn(Opcodes.GOTO, label5);
        methodVisitor.visitLabel(label);
        methodVisitor.visitVarInsn(25, context.var("lexer"));
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "nextToken", "()V");
        methodVisitor.visitLabel(label5);
    }

    private void _set(Context context, MethodVisitor methodVisitor, FieldInfo fieldInfo) {
        Method method = fieldInfo.method;
        if (method == null) {
            methodVisitor.visitFieldInsn(Opcodes.PUTFIELD, ASMUtils.type(fieldInfo.declaringClass), fieldInfo.field.getName(), ASMUtils.desc(fieldInfo.fieldClass));
            return;
        }
        methodVisitor.visitMethodInsn(method.getDeclaringClass().isInterface() ? Opcodes.INVOKEINTERFACE : Opcodes.INVOKEVIRTUAL, ASMUtils.type(fieldInfo.declaringClass), method.getName(), ASMUtils.desc(method));
        if (fieldInfo.method.getReturnType().equals(Void.TYPE)) {
            return;
        }
        methodVisitor.visitInsn(87);
    }

    private void _setContext(Context context, MethodVisitor methodVisitor) {
        methodVisitor.visitVarInsn(25, 1);
        methodVisitor.visitVarInsn(25, context.var("context"));
        String str = DefaultJSONParser;
        StringBuilder m586H = C1499a.m586H(ChineseToPinyinResource.Field.LEFT_BRACKET);
        m586H.append(ASMUtils.desc((Class<?>) ParseContext.class));
        m586H.append(")V");
        methodVisitor.visitMethodInsn(Opcodes.INVOKEVIRTUAL, str, "setContext", m586H.toString());
        Label label = new Label();
        methodVisitor.visitVarInsn(25, context.var("childContext"));
        methodVisitor.visitJumpInsn(Opcodes.IFNULL, label);
        methodVisitor.visitVarInsn(25, context.var("childContext"));
        methodVisitor.visitVarInsn(25, context.var("instance"));
        methodVisitor.visitFieldInsn(Opcodes.PUTFIELD, ASMUtils.type(ParseContext.class), "object", "Ljava/lang/Object;");
        methodVisitor.visitLabel(label);
    }

    private void _setFlag(MethodVisitor methodVisitor, Context context, int i2) {
        StringBuilder m586H = C1499a.m586H("_asm_flag_");
        m586H.append(i2 / 32);
        String sb = m586H.toString();
        methodVisitor.visitVarInsn(21, context.var(sb));
        methodVisitor.visitLdcInsn(Integer.valueOf(1 << i2));
        methodVisitor.visitInsn(128);
        methodVisitor.visitVarInsn(54, context.var(sb));
    }

    private void defineVarLexer(Context context, MethodVisitor methodVisitor) {
        methodVisitor.visitVarInsn(25, 1);
        methodVisitor.visitFieldInsn(180, DefaultJSONParser, "lexer", ASMUtils.desc((Class<?>) JSONLexer.class));
        methodVisitor.visitTypeInsn(Opcodes.CHECKCAST, JSONLexerBase);
        methodVisitor.visitVarInsn(58, context.var("lexer"));
    }

    public ObjectDeserializer createJavaBeanDeserializer(ParserConfig parserConfig, JavaBeanInfo javaBeanInfo) {
        String str;
        Class<?> cls = javaBeanInfo.clazz;
        if (cls.isPrimitive()) {
            throw new IllegalArgumentException(C1499a.m623j(cls, C1499a.m586H("not support type :")));
        }
        StringBuilder m586H = C1499a.m586H("FastjsonASMDeserializer_");
        m586H.append(this.seed.incrementAndGet());
        m586H.append("_");
        m586H.append(cls.getSimpleName());
        String sb = m586H.toString();
        Package r1 = ASMDeserializerFactory.class.getPackage();
        if (r1 != null) {
            String name = r1.getName();
            String str2 = name.replace('.', '/') + "/" + sb;
            str = C1499a.m639y(name, ".", sb);
            sb = str2;
        } else {
            str = sb;
        }
        ClassWriter classWriter = new ClassWriter();
        classWriter.visit(49, 33, sb, ASMUtils.type(JavaBeanDeserializer.class), null);
        _init(classWriter, new Context(sb, parserConfig, javaBeanInfo, 3));
        _createInstance(classWriter, new Context(sb, parserConfig, javaBeanInfo, 3));
        _deserialze(classWriter, new Context(sb, parserConfig, javaBeanInfo, 5));
        _deserialzeArrayMapping(classWriter, new Context(sb, parserConfig, javaBeanInfo, 4));
        byte[] byteArray = classWriter.toByteArray();
        return (ObjectDeserializer) this.classLoader.defineClassPublic(str, byteArray, 0, byteArray.length).getConstructor(ParserConfig.class, JavaBeanInfo.class).newInstance(parserConfig, javaBeanInfo);
    }

    private void _batchSet(Context context, MethodVisitor methodVisitor, boolean z) {
        int length = context.fieldInfoList.length;
        for (int i2 = 0; i2 < length; i2++) {
            Label label = new Label();
            if (z) {
                _isFlag(methodVisitor, context, i2, label);
            }
            _loadAndSet(context, methodVisitor, context.fieldInfoList[i2]);
            if (z) {
                methodVisitor.visitLabel(label);
            }
        }
    }

    public static class Context {
        public static final int fieldName = 3;
        public static final int parser = 1;
        public static final int type = 2;
        private final JavaBeanInfo beanInfo;
        private final String className;
        private final Class<?> clazz;
        private FieldInfo[] fieldInfoList;
        private int variantIndex;
        private final Map<String, Integer> variants = new HashMap();

        public Context(String str, ParserConfig parserConfig, JavaBeanInfo javaBeanInfo, int i2) {
            this.variantIndex = -1;
            this.className = str;
            this.clazz = javaBeanInfo.clazz;
            this.variantIndex = i2;
            this.beanInfo = javaBeanInfo;
            this.fieldInfoList = javaBeanInfo.fields;
        }

        public Class<?> getInstClass() {
            Class<?> cls = this.beanInfo.builderClass;
            return cls == null ? this.clazz : cls;
        }

        public int var(String str, int i2) {
            if (this.variants.get(str) == null) {
                this.variants.put(str, Integer.valueOf(this.variantIndex));
                this.variantIndex += i2;
            }
            return this.variants.get(str).intValue();
        }

        public int var(String str) {
            if (this.variants.get(str) == null) {
                Map<String, Integer> map = this.variants;
                int i2 = this.variantIndex;
                this.variantIndex = i2 + 1;
                map.put(str, Integer.valueOf(i2));
            }
            return this.variants.get(str).intValue();
        }
    }

    private void _createInstance(ClassWriter classWriter, Context context) {
        if (Modifier.isPublic(context.beanInfo.defaultConstructor.getModifiers())) {
            MethodWriter methodWriter = new MethodWriter(classWriter, 1, "createInstance", C1499a.m582D(C1499a.m586H("(L"), DefaultJSONParser, ";Ljava/lang/reflect/Type;)Ljava/lang/Object;"), null, null);
            methodWriter.visitTypeInsn(Opcodes.NEW, ASMUtils.type(context.getInstClass()));
            methodWriter.visitInsn(89);
            methodWriter.visitMethodInsn(Opcodes.INVOKESPECIAL, ASMUtils.type(context.getInstClass()), "<init>", "()V");
            methodWriter.visitInsn(Opcodes.ARETURN);
            methodWriter.visitMaxs(3, 3);
            methodWriter.visitEnd();
        }
    }
}
