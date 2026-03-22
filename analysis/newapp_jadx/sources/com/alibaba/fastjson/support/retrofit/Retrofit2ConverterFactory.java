package com.alibaba.fastjson.support.retrofit;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import com.alibaba.fastjson.serializer.SerializeConfig;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.alibaba.fastjson.support.config.FastJsonConfig;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.AbstractC4387j0;
import p458k.AbstractC4393m0;
import p458k.C4371b0;
import p505n.C5031z;
import p505n.InterfaceC5013h;

/* loaded from: classes.dex */
public class Retrofit2ConverterFactory extends InterfaceC5013h.a {

    @Deprecated
    private static final Feature[] EMPTY_SERIALIZER_FEATURES;
    private static final C4371b0 MEDIA_TYPE;
    private FastJsonConfig fastJsonConfig;

    @Deprecated
    private int featureValues;

    @Deprecated
    private Feature[] features;

    @Deprecated
    private ParserConfig parserConfig;

    @Deprecated
    private SerializeConfig serializeConfig;

    @Deprecated
    private SerializerFeature[] serializerFeatures;

    public final class RequestBodyConverter<T> implements InterfaceC5013h<T, AbstractC4387j0> {
        public RequestBodyConverter() {
        }

        /* JADX WARN: Multi-variable type inference failed */
        @Override // p505n.InterfaceC5013h
        public /* bridge */ /* synthetic */ AbstractC4387j0 convert(Object obj) {
            return convert2((RequestBodyConverter<T>) obj);
        }

        @Override // p505n.InterfaceC5013h
        /* renamed from: convert, reason: avoid collision after fix types in other method */
        public AbstractC4387j0 convert2(T t) {
            try {
                return AbstractC4387j0.m4986c(Retrofit2ConverterFactory.MEDIA_TYPE, JSON.toJSONBytes(Retrofit2ConverterFactory.this.fastJsonConfig.getCharset(), t, Retrofit2ConverterFactory.this.fastJsonConfig.getSerializeConfig(), Retrofit2ConverterFactory.this.fastJsonConfig.getSerializeFilters(), Retrofit2ConverterFactory.this.fastJsonConfig.getDateFormat(), JSON.DEFAULT_GENERATE_FEATURE, Retrofit2ConverterFactory.this.fastJsonConfig.getSerializerFeatures()));
            } catch (Exception e2) {
                StringBuilder m586H = C1499a.m586H("Could not write JSON: ");
                m586H.append(e2.getMessage());
                throw new IOException(m586H.toString(), e2);
            }
        }
    }

    public final class ResponseBodyConverter<T> implements InterfaceC5013h<AbstractC4393m0, T> {
        private Type type;

        public ResponseBodyConverter(Type type) {
            this.type = type;
        }

        @Override // p505n.InterfaceC5013h
        public T convert(AbstractC4393m0 abstractC4393m0) {
            try {
                try {
                    return (T) JSON.parseObject(abstractC4393m0.m5007b(), Retrofit2ConverterFactory.this.fastJsonConfig.getCharset(), this.type, Retrofit2ConverterFactory.this.fastJsonConfig.getParserConfig(), Retrofit2ConverterFactory.this.fastJsonConfig.getParseProcess(), JSON.DEFAULT_PARSER_FEATURE, Retrofit2ConverterFactory.this.fastJsonConfig.getFeatures());
                } catch (Exception e2) {
                    throw new IOException("JSON parse error: " + e2.getMessage(), e2);
                }
            } finally {
                abstractC4393m0.close();
            }
        }
    }

    static {
        C4371b0.a aVar = C4371b0.f11309c;
        MEDIA_TYPE = C4371b0.a.m4946b("application/json; charset=UTF-8");
        EMPTY_SERIALIZER_FEATURES = new Feature[0];
    }

    public Retrofit2ConverterFactory() {
        this.parserConfig = ParserConfig.getGlobalInstance();
        this.featureValues = JSON.DEFAULT_PARSER_FEATURE;
        this.fastJsonConfig = new FastJsonConfig();
    }

    public static Retrofit2ConverterFactory create() {
        return create(new FastJsonConfig());
    }

    public FastJsonConfig getFastJsonConfig() {
        return this.fastJsonConfig;
    }

    @Deprecated
    public ParserConfig getParserConfig() {
        return this.fastJsonConfig.getParserConfig();
    }

    @Deprecated
    public int getParserFeatureValues() {
        return JSON.DEFAULT_PARSER_FEATURE;
    }

    @Deprecated
    public Feature[] getParserFeatures() {
        return this.fastJsonConfig.getFeatures();
    }

    @Deprecated
    public SerializeConfig getSerializeConfig() {
        return this.fastJsonConfig.getSerializeConfig();
    }

    @Deprecated
    public SerializerFeature[] getSerializerFeatures() {
        return this.fastJsonConfig.getSerializerFeatures();
    }

    @Override // p505n.InterfaceC5013h.a
    public InterfaceC5013h<Object, AbstractC4387j0> requestBodyConverter(Type type, Annotation[] annotationArr, Annotation[] annotationArr2, C5031z c5031z) {
        return new RequestBodyConverter();
    }

    @Override // p505n.InterfaceC5013h.a
    public InterfaceC5013h<AbstractC4393m0, Object> responseBodyConverter(Type type, Annotation[] annotationArr, C5031z c5031z) {
        return new ResponseBodyConverter(type);
    }

    public Retrofit2ConverterFactory setFastJsonConfig(FastJsonConfig fastJsonConfig) {
        this.fastJsonConfig = fastJsonConfig;
        return this;
    }

    @Deprecated
    public Retrofit2ConverterFactory setParserConfig(ParserConfig parserConfig) {
        this.fastJsonConfig.setParserConfig(parserConfig);
        return this;
    }

    @Deprecated
    public Retrofit2ConverterFactory setParserFeatureValues(int i2) {
        return this;
    }

    @Deprecated
    public Retrofit2ConverterFactory setParserFeatures(Feature[] featureArr) {
        this.fastJsonConfig.setFeatures(featureArr);
        return this;
    }

    @Deprecated
    public Retrofit2ConverterFactory setSerializeConfig(SerializeConfig serializeConfig) {
        this.fastJsonConfig.setSerializeConfig(serializeConfig);
        return this;
    }

    @Deprecated
    public Retrofit2ConverterFactory setSerializerFeatures(SerializerFeature[] serializerFeatureArr) {
        this.fastJsonConfig.setSerializerFeatures(serializerFeatureArr);
        return this;
    }

    public static Retrofit2ConverterFactory create(FastJsonConfig fastJsonConfig) {
        Objects.requireNonNull(fastJsonConfig, "fastJsonConfig == null");
        return new Retrofit2ConverterFactory(fastJsonConfig);
    }

    public Retrofit2ConverterFactory(FastJsonConfig fastJsonConfig) {
        this.parserConfig = ParserConfig.getGlobalInstance();
        this.featureValues = JSON.DEFAULT_PARSER_FEATURE;
        this.fastJsonConfig = fastJsonConfig;
    }
}
