package im.uwrkaxlmjj.ui.components;

import android.graphics.Paint;
import android.graphics.drawable.ColorDrawable;
import android.util.Property;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.cells.DialogCell;

/* JADX INFO: loaded from: classes5.dex */
public class AnimationProperties {
    public static final Property<ColorDrawable, Integer> COLOR_DRAWABLE_ALPHA;
    public static final Property<Paint, Integer> PAINT_ALPHA;
    public static final Property<ClippingImageView, Float> CLIPPING_IMAGE_VIEW_PROGRESS = new FloatProperty<ClippingImageView>("animationProgress") { // from class: im.uwrkaxlmjj.ui.components.AnimationProperties.3
        @Override // im.uwrkaxlmjj.ui.components.AnimationProperties.FloatProperty
        public void setValue(ClippingImageView object, float value) {
            object.setAnimationProgress(value);
        }

        @Override // android.util.Property
        public Float get(ClippingImageView object) {
            return Float.valueOf(object.getAnimationProgress());
        }
    };
    public static final Property<PhotoViewer, Float> PHOTO_VIEWER_ANIMATION_VALUE = new FloatProperty<PhotoViewer>("animationValue") { // from class: im.uwrkaxlmjj.ui.components.AnimationProperties.4
        @Override // im.uwrkaxlmjj.ui.components.AnimationProperties.FloatProperty
        public void setValue(PhotoViewer object, float value) {
            object.setAnimationValue(value);
        }

        @Override // android.util.Property
        public Float get(PhotoViewer object) {
            return Float.valueOf(object.getAnimationValue());
        }
    };
    public static final Property<DialogCell, Float> CLIP_DIALOG_CELL_PROGRESS = new FloatProperty<DialogCell>("clipProgress") { // from class: im.uwrkaxlmjj.ui.components.AnimationProperties.5
        @Override // im.uwrkaxlmjj.ui.components.AnimationProperties.FloatProperty
        public void setValue(DialogCell object, float value) {
            object.setClipProgress(value);
        }

        @Override // android.util.Property
        public Float get(DialogCell object) {
            return Float.valueOf(object.getClipProgress());
        }
    };

    public static abstract class FloatProperty<T> extends Property<T, Float> {
        public abstract void setValue(T t, float f);

        public FloatProperty(String name) {
            super(Float.class, name);
        }

        @Override // android.util.Property
        public final void set(T object, Float value) {
            setValue(object, value.floatValue());
        }
    }

    public static abstract class IntProperty<T> extends Property<T, Integer> {
        public abstract void setValue(T t, int i);

        public IntProperty(String name) {
            super(Integer.class, name);
        }

        @Override // android.util.Property
        public final void set(T object, Integer value) {
            setValue(object, value.intValue());
        }
    }

    static {
        String str = "alpha";
        PAINT_ALPHA = new IntProperty<Paint>(str) { // from class: im.uwrkaxlmjj.ui.components.AnimationProperties.1
            @Override // im.uwrkaxlmjj.ui.components.AnimationProperties.IntProperty
            public void setValue(Paint object, int value) {
                object.setAlpha(value);
            }

            @Override // android.util.Property
            public Integer get(Paint object) {
                return Integer.valueOf(object.getAlpha());
            }
        };
        COLOR_DRAWABLE_ALPHA = new IntProperty<ColorDrawable>(str) { // from class: im.uwrkaxlmjj.ui.components.AnimationProperties.2
            @Override // im.uwrkaxlmjj.ui.components.AnimationProperties.IntProperty
            public void setValue(ColorDrawable object, int value) {
                object.setAlpha(value);
            }

            @Override // android.util.Property
            public Integer get(ColorDrawable object) {
                return Integer.valueOf(object.getAlpha());
            }
        };
    }
}
