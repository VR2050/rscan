package com.alibaba.fastjson.support.spring;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.alibaba.fastjson.util.IOUtils;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class GenericFastJsonRedisSerializer implements RedisSerializer<Object> {
    private static final ParserConfig defaultRedisConfig;

    static {
        ParserConfig parserConfig = new ParserConfig();
        defaultRedisConfig = parserConfig;
        parserConfig.setAutoTypeSupport(true);
    }

    public Object deserialize(byte[] bArr) {
        if (bArr == null || bArr.length == 0) {
            return null;
        }
        try {
            return JSON.parseObject(new String(bArr, IOUtils.UTF8), Object.class, defaultRedisConfig, new Feature[0]);
        } catch (Exception e2) {
            StringBuilder m586H = C1499a.m586H("Could not deserialize: ");
            m586H.append(e2.getMessage());
            throw new SerializationException(m586H.toString(), e2);
        }
    }

    public byte[] serialize(Object obj) {
        if (obj == null) {
            return new byte[0];
        }
        try {
            return JSON.toJSONBytes(obj, SerializerFeature.WriteClassName);
        } catch (Exception e2) {
            StringBuilder m586H = C1499a.m586H("Could not serialize: ");
            m586H.append(e2.getMessage());
            throw new SerializationException(m586H.toString(), e2);
        }
    }
}
