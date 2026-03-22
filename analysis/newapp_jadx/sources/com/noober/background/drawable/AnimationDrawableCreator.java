package com.noober.background.drawable;

import android.content.res.TypedArray;
import android.graphics.drawable.AnimationDrawable;
import android.graphics.drawable.Drawable;
import androidx.annotation.StyleableRes;
import com.noober.background.C4028R;

/* loaded from: classes2.dex */
public class AnimationDrawableCreator implements ICreateDrawable {
    private TypedArray animationTa;
    private int duration = 0;
    private AnimationDrawable drawable = new AnimationDrawable();

    public AnimationDrawableCreator(TypedArray typedArray) {
        this.animationTa = typedArray;
    }

    private void addFrame(@StyleableRes int i2, @StyleableRes int i3) {
        Drawable drawable;
        if (!this.animationTa.hasValue(i2) || (drawable = this.animationTa.getDrawable(i2)) == null) {
            return;
        }
        if (this.animationTa.hasValue(i3)) {
            this.drawable.addFrame(drawable, this.animationTa.getInt(i3, 0));
        } else {
            this.drawable.addFrame(drawable, this.duration);
        }
    }

    @Override // com.noober.background.drawable.ICreateDrawable
    public AnimationDrawable create() {
        Drawable drawable;
        for (int i2 = 0; i2 < this.animationTa.getIndexCount(); i2++) {
            int index = this.animationTa.getIndex(i2);
            if (index == C4028R.styleable.bl_anim_bl_duration) {
                this.duration = this.animationTa.getInt(index, 0);
            } else if (index == C4028R.styleable.bl_anim_bl_oneshot) {
                this.drawable.setOneShot(this.animationTa.getBoolean(index, false));
            }
        }
        TypedArray typedArray = this.animationTa;
        int i3 = C4028R.styleable.bl_anim_bl_frame_drawable_item0;
        if (typedArray.hasValue(i3) && (drawable = this.animationTa.getDrawable(i3)) != null) {
            TypedArray typedArray2 = this.animationTa;
            int i4 = C4028R.styleable.bl_anim_bl_duration_item0;
            if (typedArray2.hasValue(i4)) {
                this.drawable.addFrame(drawable, this.animationTa.getInt(i4, 0));
            } else {
                this.drawable.addFrame(drawable, this.duration);
            }
        }
        addFrame(i3, C4028R.styleable.bl_anim_bl_duration_item0);
        addFrame(C4028R.styleable.bl_anim_bl_frame_drawable_item1, C4028R.styleable.bl_anim_bl_duration_item1);
        addFrame(C4028R.styleable.bl_anim_bl_frame_drawable_item2, C4028R.styleable.bl_anim_bl_duration_item2);
        addFrame(C4028R.styleable.bl_anim_bl_frame_drawable_item3, C4028R.styleable.bl_anim_bl_duration_item3);
        addFrame(C4028R.styleable.bl_anim_bl_frame_drawable_item4, C4028R.styleable.bl_anim_bl_duration_item4);
        addFrame(C4028R.styleable.bl_anim_bl_frame_drawable_item5, C4028R.styleable.bl_anim_bl_duration_item5);
        addFrame(C4028R.styleable.bl_anim_bl_frame_drawable_item6, C4028R.styleable.bl_anim_bl_duration_item6);
        addFrame(C4028R.styleable.bl_anim_bl_frame_drawable_item7, C4028R.styleable.bl_anim_bl_duration_item7);
        addFrame(C4028R.styleable.bl_anim_bl_frame_drawable_item8, C4028R.styleable.bl_anim_bl_duration_item8);
        addFrame(C4028R.styleable.bl_anim_bl_frame_drawable_item9, C4028R.styleable.bl_anim_bl_duration_item9);
        addFrame(C4028R.styleable.bl_anim_bl_frame_drawable_item10, C4028R.styleable.bl_anim_bl_duration_item10);
        addFrame(C4028R.styleable.bl_anim_bl_frame_drawable_item11, C4028R.styleable.bl_anim_bl_duration_item11);
        addFrame(C4028R.styleable.bl_anim_bl_frame_drawable_item12, C4028R.styleable.bl_anim_bl_duration_item12);
        addFrame(C4028R.styleable.bl_anim_bl_frame_drawable_item13, C4028R.styleable.bl_anim_bl_duration_item13);
        addFrame(C4028R.styleable.bl_anim_bl_frame_drawable_item14, C4028R.styleable.bl_anim_bl_duration_item14);
        return this.drawable;
    }
}
