package com.alibaba.fastjson.support.spring;

import java.lang.reflect.Type;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;

@Deprecated
/* loaded from: classes.dex */
public class FastJsonpHttpMessageConverter4 extends FastJsonHttpMessageConverter {
    @Override // com.alibaba.fastjson.support.spring.FastJsonHttpMessageConverter
    public boolean canRead(Type type, Class<?> cls, MediaType mediaType) {
        return super.canRead(type, cls, mediaType);
    }

    @Override // com.alibaba.fastjson.support.spring.FastJsonHttpMessageConverter
    public boolean canWrite(Type type, Class<?> cls, MediaType mediaType) {
        return super.canWrite(type, cls, mediaType);
    }

    @Override // com.alibaba.fastjson.support.spring.FastJsonHttpMessageConverter
    public Object read(Type type, Class<?> cls, HttpInputMessage httpInputMessage) {
        return super.read(type, cls, httpInputMessage);
    }

    @Override // com.alibaba.fastjson.support.spring.FastJsonHttpMessageConverter
    public Object readInternal(Class<?> cls, HttpInputMessage httpInputMessage) {
        return super.readInternal(cls, httpInputMessage);
    }

    @Override // com.alibaba.fastjson.support.spring.FastJsonHttpMessageConverter
    public boolean supports(Class<?> cls) {
        return super.supports(cls);
    }

    @Override // com.alibaba.fastjson.support.spring.FastJsonHttpMessageConverter
    public void write(Object obj, Type type, MediaType mediaType, HttpOutputMessage httpOutputMessage) {
        super.write(obj, type, mediaType, httpOutputMessage);
    }

    @Override // com.alibaba.fastjson.support.spring.FastJsonHttpMessageConverter
    public void writeInternal(Object obj, HttpOutputMessage httpOutputMessage) {
        super.writeInternal(obj, httpOutputMessage);
    }
}
