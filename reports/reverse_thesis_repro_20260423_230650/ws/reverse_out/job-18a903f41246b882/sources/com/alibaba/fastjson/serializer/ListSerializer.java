package com.alibaba.fastjson.serializer;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public final class ListSerializer implements ObjectSerializer {
    public static final ListSerializer instance = new ListSerializer();

    @Override // com.alibaba.fastjson.serializer.ObjectSerializer
    public final void write(JSONSerializer serializer, Object object, Object fieldName, Type fieldType) throws Throwable {
        Type elementType;
        boolean writeClassName;
        boolean writeClassName2 = serializer.isEnabled(SerializerFeature.WriteClassName);
        SerializeWriter out = serializer.getWriter();
        int i = 0;
        if (writeClassName2 && (fieldType instanceof ParameterizedType)) {
            ParameterizedType param = (ParameterizedType) fieldType;
            Type elementType2 = param.getActualTypeArguments()[0];
            elementType = elementType2;
        } else {
            elementType = null;
        }
        if (object == null) {
            if (out.isEnabled(SerializerFeature.WriteNullListAsEmpty)) {
                out.write("[]");
                return;
            } else {
                out.writeNull();
                return;
            }
        }
        List<?> list = (List) object;
        if (list.size() == 0) {
            out.append("[]");
            return;
        }
        SerialContext context = serializer.getContext();
        serializer.setContext(context, object, fieldName, 0);
        try {
            char c = ',';
            try {
                if (out.isEnabled(SerializerFeature.PrettyFormat)) {
                    out.append('[');
                    serializer.incrementIndent();
                    int i2 = 0;
                    for (Object item : list) {
                        if (i2 != 0) {
                            out.append(c);
                        }
                        serializer.println();
                        if (item != null) {
                            if (!serializer.containsReference(item)) {
                                ObjectSerializer itemSerializer = serializer.getObjectWriter(item.getClass());
                                SerialContext itemContext = new SerialContext(context, object, fieldName, i);
                                serializer.setContext(itemContext);
                                itemSerializer.write(serializer, item, Integer.valueOf(i2), elementType);
                            } else {
                                serializer.writeReference(item);
                            }
                        } else {
                            serializer.getWriter().writeNull();
                        }
                        i2++;
                        i = 0;
                        c = ',';
                    }
                    serializer.decrementIdent();
                    serializer.println();
                    out.append(']');
                    serializer.setContext(context);
                    return;
                }
                out.append('[');
                int i3 = 0;
                for (Object item2 : list) {
                    if (i3 != 0) {
                        out.append(',');
                    }
                    if (item2 == null) {
                        out.append("null");
                        writeClassName = writeClassName2;
                    } else {
                        Class<?> clazz = item2.getClass();
                        if (clazz == Integer.class) {
                            out.writeInt(((Integer) item2).intValue());
                            writeClassName = writeClassName2;
                        } else if (clazz == Long.class) {
                            long val = ((Long) item2).longValue();
                            if (writeClassName2) {
                                writeClassName = writeClassName2;
                                try {
                                    out.writeLongAndChar(val, 'L');
                                } catch (Throwable th) {
                                    th = th;
                                }
                            } else {
                                writeClassName = writeClassName2;
                                out.writeLong(val);
                            }
                        } else {
                            writeClassName = writeClassName2;
                            SerialContext itemContext2 = new SerialContext(context, object, fieldName, 0);
                            serializer.setContext(itemContext2);
                            if (!serializer.containsReference(item2)) {
                                ObjectSerializer itemSerializer2 = serializer.getObjectWriter(item2.getClass());
                                itemSerializer2.write(serializer, item2, Integer.valueOf(i3), elementType);
                            } else {
                                serializer.writeReference(item2);
                            }
                        }
                    }
                    i3++;
                    writeClassName2 = writeClassName;
                }
                out.append(']');
                serializer.setContext(context);
                return;
            } catch (Throwable th2) {
                th = th2;
            }
        } catch (Throwable th3) {
            th = th3;
        }
        serializer.setContext(context);
        throw th;
    }
}
