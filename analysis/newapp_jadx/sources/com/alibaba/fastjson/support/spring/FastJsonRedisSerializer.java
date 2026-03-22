package com.alibaba.fastjson.support.spring;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.support.config.FastJsonConfig;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class FastJsonRedisSerializer<T> implements RedisSerializer<T> {
    private FastJsonConfig fastJsonConfig = new FastJsonConfig();
    private Class<T> type;

    public FastJsonRedisSerializer(Class<T> cls) {
        this.type = cls;
    }

    public T deserialize(byte[] bArr) {
        if (bArr == null || bArr.length == 0) {
            return null;
        }
        try {
            return (T) JSON.parseObject(bArr, this.fastJsonConfig.getCharset(), this.type, this.fastJsonConfig.getParserConfig(), this.fastJsonConfig.getParseProcess(), JSON.DEFAULT_PARSER_FEATURE, this.fastJsonConfig.getFeatures());
        } catch (Exception e2) {
            StringBuilder m586H = C1499a.m586H("Could not deserialize: ");
            m586H.append(e2.getMessage());
            throw new SerializationException(m586H.toString(), e2);
        }
    }

    public FastJsonConfig getFastJsonConfig() {
        return this.fastJsonConfig;
    }

    public byte[] serialize(T t) {
        if (t == null) {
            return new byte[0];
        }
        try {
            return JSON.toJSONBytes(this.fastJsonConfig.getCharset(), t, this.fastJsonConfig.getSerializeConfig(), this.fastJsonConfig.getSerializeFilters(), this.fastJsonConfig.getDateFormat(), JSON.DEFAULT_GENERATE_FEATURE, this.fastJsonConfig.getSerializerFeatures());
        } catch (Exception e2) {
            StringBuilder m586H = C1499a.m586H("Could not serialize: ");
            m586H.append(e2.getMessage());
            throw new SerializationException(m586H.toString(), e2);
        }
    }

    public void setFastJsonConfig(FastJsonConfig fastJsonConfig) {
        this.fastJsonConfig = fastJsonConfig;
    }
}
