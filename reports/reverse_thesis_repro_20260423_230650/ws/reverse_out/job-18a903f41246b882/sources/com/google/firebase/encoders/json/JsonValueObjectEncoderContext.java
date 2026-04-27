package com.google.firebase.encoders.json;

import android.util.Base64;
import android.util.JsonWriter;
import com.google.firebase.encoders.EncodingException;
import com.google.firebase.encoders.ObjectEncoder;
import com.google.firebase.encoders.ObjectEncoderContext;
import com.google.firebase.encoders.ValueEncoder;
import com.google.firebase.encoders.ValueEncoderContext;
import java.io.IOException;
import java.io.Writer;
import java.util.Collection;
import java.util.Map;

/* JADX INFO: compiled from: com.google.firebase:firebase-encoders-json@@16.0.0 */
/* JADX INFO: loaded from: classes.dex */
final class JsonValueObjectEncoderContext implements ObjectEncoderContext, ValueEncoderContext {
    private final JsonWriter jsonWriter;
    private final Map<Class<?>, ObjectEncoder<?>> objectEncoders;
    private final Map<Class<?>, ValueEncoder<?>> valueEncoders;
    private JsonValueObjectEncoderContext childContext = null;
    private boolean active = true;

    JsonValueObjectEncoderContext(Writer writer, Map<Class<?>, ObjectEncoder<?>> objectEncoders, Map<Class<?>, ValueEncoder<?>> valueEncoders) {
        this.jsonWriter = new JsonWriter(writer);
        this.objectEncoders = objectEncoders;
        this.valueEncoders = valueEncoders;
    }

    private JsonValueObjectEncoderContext(JsonValueObjectEncoderContext anotherContext) {
        this.jsonWriter = anotherContext.jsonWriter;
        this.objectEncoders = anotherContext.objectEncoders;
        this.valueEncoders = anotherContext.valueEncoders;
    }

    @Override // com.google.firebase.encoders.ObjectEncoderContext
    public JsonValueObjectEncoderContext add(String name, Object o) throws EncodingException, IOException {
        maybeUnNest();
        this.jsonWriter.name(name);
        if (o == null) {
            this.jsonWriter.nullValue();
            return this;
        }
        return add(o);
    }

    @Override // com.google.firebase.encoders.ObjectEncoderContext
    public JsonValueObjectEncoderContext add(String name, double value) throws EncodingException, IOException {
        maybeUnNest();
        this.jsonWriter.name(name);
        return add(value);
    }

    @Override // com.google.firebase.encoders.ObjectEncoderContext
    public JsonValueObjectEncoderContext add(String name, int value) throws EncodingException, IOException {
        maybeUnNest();
        this.jsonWriter.name(name);
        return add(value);
    }

    @Override // com.google.firebase.encoders.ObjectEncoderContext
    public JsonValueObjectEncoderContext add(String name, long value) throws EncodingException, IOException {
        maybeUnNest();
        this.jsonWriter.name(name);
        return add(value);
    }

    @Override // com.google.firebase.encoders.ObjectEncoderContext
    public JsonValueObjectEncoderContext add(String name, boolean value) throws EncodingException, IOException {
        maybeUnNest();
        this.jsonWriter.name(name);
        return add(value);
    }

    @Override // com.google.firebase.encoders.ObjectEncoderContext
    public ObjectEncoderContext nested(String name) throws IOException {
        maybeUnNest();
        this.childContext = new JsonValueObjectEncoderContext(this);
        this.jsonWriter.name(name);
        this.jsonWriter.beginObject();
        return this.childContext;
    }

    @Override // com.google.firebase.encoders.ValueEncoderContext
    public JsonValueObjectEncoderContext add(String value) throws EncodingException, IOException {
        maybeUnNest();
        this.jsonWriter.value(value);
        return this;
    }

    @Override // com.google.firebase.encoders.ValueEncoderContext
    public JsonValueObjectEncoderContext add(double value) throws EncodingException, IOException {
        maybeUnNest();
        this.jsonWriter.value(value);
        return this;
    }

    @Override // com.google.firebase.encoders.ValueEncoderContext
    public JsonValueObjectEncoderContext add(int value) throws EncodingException, IOException {
        maybeUnNest();
        this.jsonWriter.value(value);
        return this;
    }

    @Override // com.google.firebase.encoders.ValueEncoderContext
    public JsonValueObjectEncoderContext add(long value) throws EncodingException, IOException {
        maybeUnNest();
        this.jsonWriter.value(value);
        return this;
    }

    @Override // com.google.firebase.encoders.ValueEncoderContext
    public JsonValueObjectEncoderContext add(boolean value) throws EncodingException, IOException {
        maybeUnNest();
        this.jsonWriter.value(value);
        return this;
    }

    @Override // com.google.firebase.encoders.ValueEncoderContext
    public JsonValueObjectEncoderContext add(byte[] bytes) throws EncodingException, IOException {
        maybeUnNest();
        if (bytes == null) {
            this.jsonWriter.nullValue();
        } else {
            this.jsonWriter.value(Base64.encodeToString(bytes, 2));
        }
        return this;
    }

    JsonValueObjectEncoderContext add(Object o) throws EncodingException, IOException {
        if (o == null) {
            this.jsonWriter.nullValue();
            return this;
        }
        if (o instanceof Number) {
            this.jsonWriter.value((Number) o);
            return this;
        }
        int i = 0;
        if (o.getClass().isArray()) {
            if (o instanceof byte[]) {
                return add((byte[]) o);
            }
            this.jsonWriter.beginArray();
            if (o instanceof int[]) {
                int[] iArr = (int[]) o;
                int length = iArr.length;
                while (i < length) {
                    int item = iArr[i];
                    this.jsonWriter.value(item);
                    i++;
                }
            } else if (o instanceof long[]) {
                long[] jArr = (long[]) o;
                int length2 = jArr.length;
                while (i < length2) {
                    long item2 = jArr[i];
                    add(item2);
                    i++;
                }
            } else if (o instanceof double[]) {
                double[] dArr = (double[]) o;
                int length3 = dArr.length;
                while (i < length3) {
                    double item3 = dArr[i];
                    this.jsonWriter.value(item3);
                    i++;
                }
            } else if (o instanceof boolean[]) {
                boolean[] zArr = (boolean[]) o;
                int length4 = zArr.length;
                while (i < length4) {
                    boolean item4 = zArr[i];
                    this.jsonWriter.value(item4);
                    i++;
                }
            } else if (o instanceof Number[]) {
                Number[] numberArr = (Number[]) o;
                int length5 = numberArr.length;
                while (i < length5) {
                    Number item5 = numberArr[i];
                    add(item5);
                    i++;
                }
            } else {
                Object[] objArr = (Object[]) o;
                int length6 = objArr.length;
                while (i < length6) {
                    Object item6 = objArr[i];
                    add(item6);
                    i++;
                }
            }
            this.jsonWriter.endArray();
            return this;
        }
        if (o instanceof Collection) {
            Collection collection = (Collection) o;
            this.jsonWriter.beginArray();
            for (Object elem : collection) {
                add(elem);
            }
            this.jsonWriter.endArray();
            return this;
        }
        if (o instanceof Map) {
            Map<Object, Object> map = (Map) o;
            this.jsonWriter.beginObject();
            for (Map.Entry<Object, Object> entry : map.entrySet()) {
                Object key = entry.getKey();
                try {
                    add((String) key, entry.getValue());
                } catch (ClassCastException ex) {
                    throw new EncodingException(String.format("Only String keys are currently supported in maps, got %s of type %s instead.", key, key.getClass()), ex);
                }
            }
            this.jsonWriter.endObject();
            return this;
        }
        Map<Object, Object> map2 = this.objectEncoders;
        ObjectEncoder<?> objectEncoder = (ObjectEncoder) map2.get(o.getClass());
        if (objectEncoder != null) {
            this.jsonWriter.beginObject();
            objectEncoder.encode(o, this);
            this.jsonWriter.endObject();
            return this;
        }
        ValueEncoder<?> valueEncoder = this.valueEncoders.get(o.getClass());
        if (valueEncoder != null) {
            valueEncoder.encode(o, this);
            return this;
        }
        if (o instanceof Enum) {
            add(((Enum) o).name());
            return this;
        }
        throw new EncodingException("Couldn't find encoder for type " + o.getClass().getCanonicalName());
    }

    void close() throws IOException {
        maybeUnNest();
        this.jsonWriter.flush();
    }

    private void maybeUnNest() throws IOException {
        if (!this.active) {
            throw new IllegalStateException("Parent context used since this context was created. Cannot use this context anymore.");
        }
        JsonValueObjectEncoderContext jsonValueObjectEncoderContext = this.childContext;
        if (jsonValueObjectEncoderContext != null) {
            jsonValueObjectEncoderContext.maybeUnNest();
            this.childContext.active = false;
            this.childContext = null;
            this.jsonWriter.endObject();
        }
    }
}
