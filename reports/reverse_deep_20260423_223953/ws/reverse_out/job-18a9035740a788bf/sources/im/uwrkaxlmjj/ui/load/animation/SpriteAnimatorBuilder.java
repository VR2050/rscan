package im.uwrkaxlmjj.ui.load.animation;

import android.animation.Keyframe;
import android.animation.ObjectAnimator;
import android.animation.PropertyValuesHolder;
import android.util.Log;
import android.util.Property;
import android.view.animation.Interpolator;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import im.uwrkaxlmjj.ui.load.animation.interpolator.KeyFrameInterpolator;
import im.uwrkaxlmjj.ui.load.sprite.Sprite;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/* JADX INFO: loaded from: classes5.dex */
public class SpriteAnimatorBuilder {
    private static final String TAG = "SpriteAnimatorBuilder";
    private Interpolator interpolator;
    private Sprite sprite;
    private int repeatCount = -1;
    private long duration = AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS;
    private int startFrame = 0;
    private Map<String, FrameData> fds = new HashMap();

    class FrameData<T> {
        float[] fractions;
        Property property;
        T[] values;

        public FrameData(float[] fractions, Property property, T[] values) {
            this.fractions = fractions;
            this.property = property;
            this.values = values;
        }
    }

    class IntFrameData extends FrameData<Integer> {
        public IntFrameData(float[] fractions, Property property, Integer[] values) {
            super(fractions, property, values);
        }
    }

    class FloatFrameData extends FrameData<Float> {
        public FloatFrameData(float[] fractions, Property property, Float[] values) {
            super(fractions, property, values);
        }
    }

    public SpriteAnimatorBuilder(Sprite sprite) {
        this.sprite = sprite;
    }

    public SpriteAnimatorBuilder scale(float[] fractions, Float... scale) {
        holder(fractions, Sprite.SCALE, scale);
        return this;
    }

    public SpriteAnimatorBuilder alpha(float[] fractions, Integer... alpha) {
        holder(fractions, Sprite.ALPHA, alpha);
        return this;
    }

    public SpriteAnimatorBuilder scaleX(float[] fractions, Float... scaleX) {
        holder(fractions, Sprite.SCALE, scaleX);
        return this;
    }

    public SpriteAnimatorBuilder scaleY(float[] fractions, Float... scaleY) {
        holder(fractions, Sprite.SCALE_Y, scaleY);
        return this;
    }

    public SpriteAnimatorBuilder rotateX(float[] fractions, Integer... rotateX) {
        holder(fractions, Sprite.ROTATE_X, rotateX);
        return this;
    }

    public SpriteAnimatorBuilder rotateY(float[] fractions, Integer... rotateY) {
        holder(fractions, Sprite.ROTATE_Y, rotateY);
        return this;
    }

    public SpriteAnimatorBuilder translateX(float[] fractions, Integer... translateX) {
        holder(fractions, Sprite.TRANSLATE_X, translateX);
        return this;
    }

    public SpriteAnimatorBuilder translateY(float[] fractions, Integer... translateY) {
        holder(fractions, Sprite.TRANSLATE_Y, translateY);
        return this;
    }

    public SpriteAnimatorBuilder rotate(float[] fractions, Integer... rotate) {
        holder(fractions, Sprite.ROTATE, rotate);
        return this;
    }

    public SpriteAnimatorBuilder translateXPercentage(float[] fractions, Float... translateXPercentage) {
        holder(fractions, Sprite.TRANSLATE_X_PERCENTAGE, translateXPercentage);
        return this;
    }

    public SpriteAnimatorBuilder translateYPercentage(float[] fractions, Float... translateYPercentage) {
        holder(fractions, Sprite.TRANSLATE_Y_PERCENTAGE, translateYPercentage);
        return this;
    }

    private void holder(float[] fractions, Property property, Float[] values) {
        ensurePair(fractions.length, values.length);
        this.fds.put(property.getName(), new FloatFrameData(fractions, property, values));
    }

    private void holder(float[] fractions, Property property, Integer[] values) {
        ensurePair(fractions.length, values.length);
        this.fds.put(property.getName(), new IntFrameData(fractions, property, values));
    }

    private void ensurePair(int fractionsLength, int valuesLength) {
        if (fractionsLength != valuesLength) {
            throw new IllegalStateException(String.format(Locale.getDefault(), "The fractions.length must equal values.length, fraction.length[%d], values.length[%d]", Integer.valueOf(fractionsLength), Integer.valueOf(valuesLength)));
        }
    }

    public SpriteAnimatorBuilder interpolator(Interpolator interpolator) {
        this.interpolator = interpolator;
        return this;
    }

    public SpriteAnimatorBuilder easeInOut(float... fractions) {
        interpolator(KeyFrameInterpolator.easeInOut(fractions));
        return this;
    }

    public SpriteAnimatorBuilder duration(long duration) {
        this.duration = duration;
        return this;
    }

    public SpriteAnimatorBuilder repeatCount(int repeatCount) {
        this.repeatCount = repeatCount;
        return this;
    }

    public SpriteAnimatorBuilder startFrame(int startFrame) {
        if (startFrame < 0) {
            Log.w(TAG, "startFrame should always be non-negative");
            startFrame = 0;
        }
        this.startFrame = startFrame;
        return this;
    }

    public ObjectAnimator build() {
        PropertyValuesHolder[] holders = new PropertyValuesHolder[this.fds.size()];
        int i = 0;
        for (Map.Entry<String, FrameData> fd : this.fds.entrySet()) {
            FrameData data = fd.getValue();
            Keyframe[] keyframes = new Keyframe[data.fractions.length];
            float[] fractions = data.fractions;
            float startF = fractions[this.startFrame];
            for (int j = this.startFrame; j < this.startFrame + data.values.length; j++) {
                int key = j - this.startFrame;
                int vk = j % data.values.length;
                float fraction = fractions[vk] - startF;
                if (fraction < 0.0f) {
                    fraction += fractions[fractions.length - 1];
                }
                if (data instanceof IntFrameData) {
                    keyframes[key] = Keyframe.ofInt(fraction, ((Integer) data.values[vk]).intValue());
                } else if (data instanceof FloatFrameData) {
                    keyframes[key] = Keyframe.ofFloat(fraction, ((Float) data.values[vk]).floatValue());
                } else {
                    keyframes[key] = Keyframe.ofObject(fraction, data.values[vk]);
                }
            }
            holders[i] = PropertyValuesHolder.ofKeyframe(data.property, keyframes);
            i++;
        }
        ObjectAnimator animator = ObjectAnimator.ofPropertyValuesHolder(this.sprite, holders);
        animator.setDuration(this.duration);
        animator.setRepeatCount(this.repeatCount);
        animator.setInterpolator(this.interpolator);
        return animator;
    }
}
