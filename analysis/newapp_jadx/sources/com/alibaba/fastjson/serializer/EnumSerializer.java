package com.alibaba.fastjson.serializer;

import java.lang.reflect.Type;

/* loaded from: classes.dex */
public class EnumSerializer implements ObjectSerializer {
    public static final EnumSerializer instance = new EnumSerializer();

    @Override // com.alibaba.fastjson.serializer.ObjectSerializer
    public void write(JSONSerializer jSONSerializer, Object obj, Object obj2, Type type, int i2) {
        jSONSerializer.out.writeEnum((Enum) obj);
    }
}
