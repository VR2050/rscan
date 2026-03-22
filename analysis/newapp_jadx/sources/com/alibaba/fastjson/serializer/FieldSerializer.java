package com.alibaba.fastjson.serializer;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.annotation.JSONField;
import com.alibaba.fastjson.annotation.JSONType;
import com.alibaba.fastjson.util.FieldInfo;
import com.alibaba.fastjson.util.TypeUtils;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import kotlin.text.Typography;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class FieldSerializer implements Comparable<FieldSerializer> {
    public boolean browserCompatible;
    public boolean disableCircularReferenceDetect;
    private final String double_quoted_fieldPrefix;
    public int features;
    public BeanContext fieldContext;
    public final FieldInfo fieldInfo;
    private String format;
    public boolean persistenceXToMany;
    private RuntimeSerializerInfo runtimeInfo;
    public boolean serializeUsing = false;
    private String single_quoted_fieldPrefix;
    private String un_quoted_fieldPrefix;
    public boolean writeEnumUsingName;
    public boolean writeEnumUsingToString;
    public final boolean writeNull;

    public static class RuntimeSerializerInfo {
        public final ObjectSerializer fieldSerializer;
        public final Class<?> runtimeFieldClass;

        public RuntimeSerializerInfo(ObjectSerializer objectSerializer, Class<?> cls) {
            this.fieldSerializer = objectSerializer;
            this.runtimeFieldClass = cls;
        }
    }

    public FieldSerializer(Class<?> cls, FieldInfo fieldInfo) {
        boolean z;
        JSONType jSONType;
        this.writeEnumUsingToString = false;
        this.writeEnumUsingName = false;
        this.disableCircularReferenceDetect = false;
        this.persistenceXToMany = false;
        this.fieldInfo = fieldInfo;
        this.fieldContext = new BeanContext(cls, fieldInfo);
        if (cls != null && (jSONType = (JSONType) TypeUtils.getAnnotation(cls, JSONType.class)) != null) {
            for (SerializerFeature serializerFeature : jSONType.serialzeFeatures()) {
                if (serializerFeature == SerializerFeature.WriteEnumUsingToString) {
                    this.writeEnumUsingToString = true;
                } else if (serializerFeature == SerializerFeature.WriteEnumUsingName) {
                    this.writeEnumUsingName = true;
                } else if (serializerFeature == SerializerFeature.DisableCircularReferenceDetect) {
                    this.disableCircularReferenceDetect = true;
                } else {
                    SerializerFeature serializerFeature2 = SerializerFeature.BrowserCompatible;
                    if (serializerFeature == serializerFeature2) {
                        this.features |= serializerFeature2.mask;
                        this.browserCompatible = true;
                    } else {
                        SerializerFeature serializerFeature3 = SerializerFeature.WriteMapNullValue;
                        if (serializerFeature == serializerFeature3) {
                            this.features |= serializerFeature3.mask;
                        }
                    }
                }
            }
        }
        fieldInfo.setAccessible();
        StringBuilder sb = new StringBuilder();
        sb.append(Typography.quote);
        this.double_quoted_fieldPrefix = C1499a.m582D(sb, fieldInfo.name, "\":");
        JSONField annotation = fieldInfo.getAnnotation();
        if (annotation != null) {
            SerializerFeature[] serialzeFeatures = annotation.serialzeFeatures();
            int length = serialzeFeatures.length;
            int i2 = 0;
            while (true) {
                if (i2 >= length) {
                    z = false;
                    break;
                } else {
                    if ((serialzeFeatures[i2].getMask() & SerializerFeature.WRITE_MAP_NULL_FEATURES) != 0) {
                        z = true;
                        break;
                    }
                    i2++;
                }
            }
            String format = annotation.format();
            this.format = format;
            if (format.trim().length() == 0) {
                this.format = null;
            }
            for (SerializerFeature serializerFeature4 : annotation.serialzeFeatures()) {
                if (serializerFeature4 == SerializerFeature.WriteEnumUsingToString) {
                    this.writeEnumUsingToString = true;
                } else if (serializerFeature4 == SerializerFeature.WriteEnumUsingName) {
                    this.writeEnumUsingName = true;
                } else if (serializerFeature4 == SerializerFeature.DisableCircularReferenceDetect) {
                    this.disableCircularReferenceDetect = true;
                } else if (serializerFeature4 == SerializerFeature.BrowserCompatible) {
                    this.browserCompatible = true;
                }
            }
            this.features = SerializerFeature.m3646of(annotation.serialzeFeatures()) | this.features;
        } else {
            z = false;
        }
        this.writeNull = z;
        this.persistenceXToMany = TypeUtils.isAnnotationPresentOneToMany(fieldInfo.method) || TypeUtils.isAnnotationPresentManyToMany(fieldInfo.method);
    }

    public Object getPropertyValue(Object obj) {
        Object obj2 = this.fieldInfo.get(obj);
        if (this.format == null || obj2 == null) {
            return obj2;
        }
        Class<?> cls = this.fieldInfo.fieldClass;
        if (cls != Date.class && cls != java.sql.Date.class) {
            return obj2;
        }
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(this.format, JSON.defaultLocale);
        simpleDateFormat.setTimeZone(JSON.defaultTimeZone);
        return simpleDateFormat.format(obj2);
    }

    public Object getPropertyValueDirect(Object obj) {
        Object obj2 = this.fieldInfo.get(obj);
        if (!this.persistenceXToMany || TypeUtils.isHibernateInitialized(obj2)) {
            return obj2;
        }
        return null;
    }

    public void writePrefix(JSONSerializer jSONSerializer) {
        SerializeWriter serializeWriter = jSONSerializer.out;
        if (!serializeWriter.quoteFieldNames) {
            if (this.un_quoted_fieldPrefix == null) {
                this.un_quoted_fieldPrefix = C1499a.m582D(new StringBuilder(), this.fieldInfo.name, ":");
            }
            serializeWriter.write(this.un_quoted_fieldPrefix);
        } else {
            if (!SerializerFeature.isEnabled(serializeWriter.features, this.fieldInfo.serialzeFeatures, SerializerFeature.UseSingleQuotes)) {
                serializeWriter.write(this.double_quoted_fieldPrefix);
                return;
            }
            if (this.single_quoted_fieldPrefix == null) {
                this.single_quoted_fieldPrefix = C1499a.m582D(C1499a.m584F('\''), this.fieldInfo.name, "':");
            }
            serializeWriter.write(this.single_quoted_fieldPrefix);
        }
    }

    public void writeValue(JSONSerializer jSONSerializer, Object obj) {
        Class<?> cls;
        Class<?> cls2;
        ObjectSerializer objectWriter;
        if (this.runtimeInfo == null) {
            if (obj == null) {
                cls2 = this.fieldInfo.fieldClass;
                if (cls2 == Byte.TYPE) {
                    cls2 = Byte.class;
                } else if (cls2 == Short.TYPE) {
                    cls2 = Short.class;
                } else if (cls2 == Integer.TYPE) {
                    cls2 = Integer.class;
                } else if (cls2 == Long.TYPE) {
                    cls2 = Long.class;
                } else if (cls2 == Float.TYPE) {
                    cls2 = Float.class;
                } else if (cls2 == Double.TYPE) {
                    cls2 = Double.class;
                } else if (cls2 == Boolean.TYPE) {
                    cls2 = Boolean.class;
                }
            } else {
                cls2 = obj.getClass();
            }
            ObjectSerializer objectSerializer = null;
            JSONField annotation = this.fieldInfo.getAnnotation();
            if (annotation == null || annotation.serializeUsing() == Void.class) {
                if (this.format != null) {
                    if (cls2 == Double.TYPE || cls2 == Double.class) {
                        objectSerializer = new DoubleSerializer(this.format);
                    } else if (cls2 == Float.TYPE || cls2 == Float.class) {
                        objectSerializer = new FloatCodec(this.format);
                    }
                }
                objectWriter = objectSerializer == null ? jSONSerializer.getObjectWriter(cls2) : objectSerializer;
            } else {
                objectWriter = (ObjectSerializer) annotation.serializeUsing().newInstance();
                this.serializeUsing = true;
            }
            this.runtimeInfo = new RuntimeSerializerInfo(objectWriter, cls2);
        }
        RuntimeSerializerInfo runtimeSerializerInfo = this.runtimeInfo;
        int i2 = (this.disableCircularReferenceDetect ? this.fieldInfo.serialzeFeatures | SerializerFeature.DisableCircularReferenceDetect.mask : this.fieldInfo.serialzeFeatures) | this.features;
        if (obj == null) {
            SerializeWriter serializeWriter = jSONSerializer.out;
            if (this.fieldInfo.fieldClass == Object.class && serializeWriter.isEnabled(SerializerFeature.WRITE_MAP_NULL_FEATURES)) {
                serializeWriter.writeNull();
                return;
            }
            Class<?> cls3 = runtimeSerializerInfo.runtimeFieldClass;
            if (Number.class.isAssignableFrom(cls3)) {
                serializeWriter.writeNull(this.features, SerializerFeature.WriteNullNumberAsZero.mask);
                return;
            }
            if (String.class == cls3) {
                serializeWriter.writeNull(this.features, SerializerFeature.WriteNullStringAsEmpty.mask);
                return;
            }
            if (Boolean.class == cls3) {
                serializeWriter.writeNull(this.features, SerializerFeature.WriteNullBooleanAsFalse.mask);
                return;
            }
            if (Collection.class.isAssignableFrom(cls3) || cls3.isArray()) {
                serializeWriter.writeNull(this.features, SerializerFeature.WriteNullListAsEmpty.mask);
                return;
            }
            ObjectSerializer objectSerializer2 = runtimeSerializerInfo.fieldSerializer;
            if (serializeWriter.isEnabled(SerializerFeature.WRITE_MAP_NULL_FEATURES) && (objectSerializer2 instanceof JavaBeanSerializer)) {
                serializeWriter.writeNull();
                return;
            } else {
                FieldInfo fieldInfo = this.fieldInfo;
                objectSerializer2.write(jSONSerializer, null, fieldInfo.name, fieldInfo.fieldType, i2);
                return;
            }
        }
        if (this.fieldInfo.isEnum) {
            if (this.writeEnumUsingName) {
                jSONSerializer.out.writeString(((Enum) obj).name());
                return;
            } else if (this.writeEnumUsingToString) {
                jSONSerializer.out.writeString(((Enum) obj).toString());
                return;
            }
        }
        Class<?> cls4 = obj.getClass();
        ObjectSerializer objectWriter2 = (cls4 == runtimeSerializerInfo.runtimeFieldClass || this.serializeUsing) ? runtimeSerializerInfo.fieldSerializer : jSONSerializer.getObjectWriter(cls4);
        String str = this.format;
        if (str != null && !(objectWriter2 instanceof DoubleSerializer) && !(objectWriter2 instanceof FloatCodec)) {
            if (objectWriter2 instanceof ContextObjectSerializer) {
                ((ContextObjectSerializer) objectWriter2).write(jSONSerializer, obj, this.fieldContext);
                return;
            } else {
                jSONSerializer.writeWithFormat(obj, str);
                return;
            }
        }
        FieldInfo fieldInfo2 = this.fieldInfo;
        if (fieldInfo2.unwrapped) {
            if (objectWriter2 instanceof JavaBeanSerializer) {
                ((JavaBeanSerializer) objectWriter2).write(jSONSerializer, obj, fieldInfo2.name, fieldInfo2.fieldType, i2, true);
                return;
            } else if (objectWriter2 instanceof MapSerializer) {
                ((MapSerializer) objectWriter2).write(jSONSerializer, obj, fieldInfo2.name, fieldInfo2.fieldType, i2, true);
                return;
            }
        }
        if ((this.features & SerializerFeature.WriteClassName.mask) != 0 && cls4 != fieldInfo2.fieldClass && (objectWriter2 instanceof JavaBeanSerializer)) {
            ((JavaBeanSerializer) objectWriter2).write(jSONSerializer, obj, fieldInfo2.name, fieldInfo2.fieldType, i2, false);
            return;
        }
        if (this.browserCompatible && ((cls = fieldInfo2.fieldClass) == Long.TYPE || cls == Long.class)) {
            long longValue = ((Long) obj).longValue();
            if (longValue > 9007199254740991L || longValue < -9007199254740991L) {
                jSONSerializer.getWriter().writeString(Long.toString(longValue));
                return;
            }
        }
        FieldInfo fieldInfo3 = this.fieldInfo;
        objectWriter2.write(jSONSerializer, obj, fieldInfo3.name, fieldInfo3.fieldType, i2);
    }

    @Override // java.lang.Comparable
    public int compareTo(FieldSerializer fieldSerializer) {
        return this.fieldInfo.compareTo(fieldSerializer.fieldInfo);
    }
}
