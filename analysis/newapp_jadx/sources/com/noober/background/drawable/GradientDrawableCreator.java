package com.noober.background.drawable;

import android.R;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import com.noober.background.C4028R;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Iterator;
import org.xmlpull.v1.XmlPullParserException;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class GradientDrawableCreator implements ICreateDrawable {
    private TypedArray typedArray;

    public GradientDrawableCreator(TypedArray typedArray) {
        this.typedArray = typedArray;
    }

    private boolean hasSetRadius(float[] fArr) {
        for (float f2 : fArr) {
            if (f2 != 0.0f) {
                return true;
            }
        }
        return false;
    }

    @Override // com.noober.background.drawable.ICreateDrawable
    public GradientDrawable create() {
        float f2;
        int color;
        GradientDrawable gradientDrawable = new GradientDrawable();
        float[] fArr = new float[8];
        Rect rect = new Rect();
        int i2 = 0;
        int i3 = 0;
        float f3 = 0.0f;
        float f4 = 0.0f;
        int i4 = 0;
        float f5 = -1.0f;
        float f6 = 0.0f;
        int i5 = 0;
        float f7 = 0.0f;
        float f8 = 0.0f;
        float f9 = 0.0f;
        int i6 = 0;
        int i7 = 0;
        int i8 = 0;
        int i9 = 0;
        int i10 = 0;
        while (i3 < this.typedArray.getIndexCount()) {
            int index = this.typedArray.getIndex(i3);
            float f10 = f8;
            if (index == C4028R.styleable.background_bl_shape) {
                gradientDrawable.setShape(this.typedArray.getInt(index, i2));
            } else {
                if (index == C4028R.styleable.background_bl_solid_color) {
                    i4 = this.typedArray.getColor(index, i2);
                } else if (index == C4028R.styleable.background_bl_corners_radius) {
                    gradientDrawable.setCornerRadius(this.typedArray.getDimension(index, 0.0f));
                } else {
                    if (index == C4028R.styleable.background_bl_corners_bottomLeftRadius) {
                        f2 = f9;
                        fArr[6] = this.typedArray.getDimension(index, 0.0f);
                        fArr[7] = this.typedArray.getDimension(index, 0.0f);
                    } else {
                        f2 = f9;
                        if (index == C4028R.styleable.background_bl_corners_bottomRightRadius) {
                            fArr[4] = this.typedArray.getDimension(index, 0.0f);
                            fArr[5] = this.typedArray.getDimension(index, 0.0f);
                        } else if (index == C4028R.styleable.background_bl_corners_topLeftRadius) {
                            fArr[0] = this.typedArray.getDimension(index, 0.0f);
                            fArr[1] = this.typedArray.getDimension(index, 0.0f);
                        } else if (index == C4028R.styleable.background_bl_corners_topRightRadius) {
                            fArr[2] = this.typedArray.getDimension(index, 0.0f);
                            fArr[3] = this.typedArray.getDimension(index, 0.0f);
                        } else {
                            if (index == C4028R.styleable.background_bl_gradient_angle) {
                                i10 = this.typedArray.getInteger(index, 0);
                            } else if (index == C4028R.styleable.background_bl_gradient_centerX) {
                                f8 = this.typedArray.getFloat(index, -1.0f);
                                color = i9;
                                f9 = f2;
                                i9 = color;
                                i3++;
                                i2 = 0;
                            } else if (index == C4028R.styleable.background_bl_gradient_centerY) {
                                f9 = this.typedArray.getFloat(index, -1.0f);
                            } else if (index == C4028R.styleable.background_bl_gradient_centerColor) {
                                color = this.typedArray.getColor(index, 0);
                                f9 = f2;
                                f8 = f10;
                                i9 = color;
                                i3++;
                                i2 = 0;
                            } else if (index == C4028R.styleable.background_bl_gradient_endColor) {
                                i7 = this.typedArray.getColor(index, 0);
                            } else if (index == C4028R.styleable.background_bl_gradient_startColor) {
                                i6 = this.typedArray.getColor(index, 0);
                            } else if (index == C4028R.styleable.background_bl_gradient_gradientRadius) {
                                gradientDrawable.setGradientRadius(this.typedArray.getDimension(index, 0.0f));
                            } else if (index == C4028R.styleable.background_bl_gradient_type) {
                                int i11 = this.typedArray.getInt(index, 0);
                                gradientDrawable.setGradientType(i11);
                                i8 = i11;
                            } else if (index == C4028R.styleable.background_bl_gradient_useLevel) {
                                gradientDrawable.setUseLevel(this.typedArray.getBoolean(index, false));
                            } else if (index == C4028R.styleable.background_bl_padding_left) {
                                rect.left = (int) this.typedArray.getDimension(index, 0.0f);
                            } else if (index == C4028R.styleable.background_bl_padding_top) {
                                rect.top = (int) this.typedArray.getDimension(index, 0.0f);
                            } else if (index == C4028R.styleable.background_bl_padding_right) {
                                rect.right = (int) this.typedArray.getDimension(index, 0.0f);
                            } else if (index == C4028R.styleable.background_bl_padding_bottom) {
                                rect.bottom = (int) this.typedArray.getDimension(index, 0.0f);
                            } else if (index == C4028R.styleable.background_bl_size_width) {
                                f3 = this.typedArray.getDimension(index, 0.0f);
                            } else if (index == C4028R.styleable.background_bl_size_height) {
                                f4 = this.typedArray.getDimension(index, 0.0f);
                            } else if (index == C4028R.styleable.background_bl_stroke_width) {
                                f5 = this.typedArray.getDimension(index, 0.0f);
                            } else if (index == C4028R.styleable.background_bl_stroke_color) {
                                i5 = this.typedArray.getColor(index, 0);
                            } else if (index == C4028R.styleable.background_bl_stroke_dashWidth) {
                                f6 = this.typedArray.getDimension(index, 0.0f);
                            } else if (index == C4028R.styleable.background_bl_stroke_dashGap) {
                                f7 = this.typedArray.getDimension(index, 0.0f);
                            }
                            color = i9;
                            f9 = f2;
                            f8 = f10;
                            i9 = color;
                            i3++;
                            i2 = 0;
                        }
                    }
                    f8 = f10;
                    f9 = f2;
                    i3++;
                    i2 = 0;
                }
                color = i9;
                f8 = f10;
                i9 = color;
                i3++;
                i2 = 0;
            }
            f2 = f9;
            f8 = f10;
            f9 = f2;
            i3++;
            i2 = 0;
        }
        float f11 = f8;
        float f12 = f9;
        if (hasSetRadius(fArr)) {
            gradientDrawable.setCornerRadii(fArr);
        }
        if (this.typedArray.hasValue(C4028R.styleable.background_bl_size_width) && this.typedArray.hasValue(C4028R.styleable.background_bl_size_height)) {
            gradientDrawable.setSize((int) f3, (int) f4);
        }
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        TypedArray typedArray = this.typedArray;
        int i12 = C4028R.styleable.background_bl_pressed_solid_color;
        if (typedArray.hasValue(i12)) {
            arrayList.add(Integer.valueOf(R.attr.state_pressed));
            C1499a.m603Y(this.typedArray, i12, 0, arrayList2);
        }
        TypedArray typedArray2 = this.typedArray;
        int i13 = C4028R.styleable.background_bl_unPressed_solid_color;
        if (typedArray2.hasValue(i13)) {
            arrayList.add(-16842919);
            C1499a.m603Y(this.typedArray, i13, 0, arrayList2);
        }
        TypedArray typedArray3 = this.typedArray;
        int i14 = C4028R.styleable.background_bl_checkable_solid_color;
        if (typedArray3.hasValue(i14)) {
            arrayList.add(Integer.valueOf(R.attr.state_checkable));
            C1499a.m603Y(this.typedArray, i14, 0, arrayList2);
        }
        TypedArray typedArray4 = this.typedArray;
        int i15 = C4028R.styleable.background_bl_unCheckable_solid_color;
        if (typedArray4.hasValue(i15)) {
            arrayList.add(-16842911);
            C1499a.m603Y(this.typedArray, i15, 0, arrayList2);
        }
        TypedArray typedArray5 = this.typedArray;
        int i16 = C4028R.styleable.background_bl_checked_solid_color;
        if (typedArray5.hasValue(i16)) {
            arrayList.add(Integer.valueOf(R.attr.state_checked));
            C1499a.m603Y(this.typedArray, i16, 0, arrayList2);
        }
        TypedArray typedArray6 = this.typedArray;
        int i17 = C4028R.styleable.background_bl_unChecked_solid_color;
        if (typedArray6.hasValue(i17)) {
            arrayList.add(-16842912);
            C1499a.m603Y(this.typedArray, i17, 0, arrayList2);
        }
        TypedArray typedArray7 = this.typedArray;
        int i18 = C4028R.styleable.background_bl_enabled_solid_color;
        if (typedArray7.hasValue(i18)) {
            arrayList.add(Integer.valueOf(R.attr.state_enabled));
            C1499a.m603Y(this.typedArray, i18, 0, arrayList2);
        }
        TypedArray typedArray8 = this.typedArray;
        int i19 = C4028R.styleable.background_bl_unEnabled_solid_color;
        if (typedArray8.hasValue(i19)) {
            arrayList.add(-16842910);
            C1499a.m603Y(this.typedArray, i19, 0, arrayList2);
        }
        TypedArray typedArray9 = this.typedArray;
        int i20 = C4028R.styleable.background_bl_selected_solid_color;
        if (typedArray9.hasValue(i20)) {
            arrayList.add(Integer.valueOf(R.attr.state_selected));
            C1499a.m603Y(this.typedArray, i20, 0, arrayList2);
        }
        TypedArray typedArray10 = this.typedArray;
        int i21 = C4028R.styleable.background_bl_unSelected_solid_color;
        if (typedArray10.hasValue(i21)) {
            arrayList.add(-16842913);
            C1499a.m603Y(this.typedArray, i21, 0, arrayList2);
        }
        TypedArray typedArray11 = this.typedArray;
        int i22 = C4028R.styleable.background_bl_focused_solid_color;
        if (typedArray11.hasValue(i22)) {
            arrayList.add(Integer.valueOf(R.attr.state_focused));
            C1499a.m603Y(this.typedArray, i22, 0, arrayList2);
        }
        TypedArray typedArray12 = this.typedArray;
        int i23 = C4028R.styleable.background_bl_unFocused_solid_color;
        if (typedArray12.hasValue(i23)) {
            arrayList.add(-16842908);
            C1499a.m603Y(this.typedArray, i23, 0, arrayList2);
        }
        if (arrayList.size() > 0) {
            int size = arrayList.size();
            if (this.typedArray.hasValue(C4028R.styleable.background_bl_solid_color)) {
                size++;
            }
            int[][] iArr = new int[size][];
            int[] iArr2 = new int[size];
            Iterator it = arrayList.iterator();
            int i24 = 0;
            while (it.hasNext()) {
                iArr[i24] = new int[]{((Integer) it.next()).intValue()};
                iArr2[i24] = ((Integer) arrayList2.get(i24)).intValue();
                i24++;
            }
            if (this.typedArray.hasValue(C4028R.styleable.background_bl_solid_color)) {
                iArr[i24] = new int[0];
                iArr2[i24] = i4;
            }
            gradientDrawable.setColor(new ColorStateList(iArr, iArr2));
        } else if (this.typedArray.hasValue(C4028R.styleable.background_bl_solid_color)) {
            gradientDrawable.setColor(i4);
        }
        if (this.typedArray.hasValue(C4028R.styleable.background_bl_stroke_width)) {
            ArrayList arrayList3 = new ArrayList();
            ArrayList arrayList4 = new ArrayList();
            TypedArray typedArray13 = this.typedArray;
            int i25 = C4028R.styleable.background_bl_pressed_stroke_color;
            if (typedArray13.hasValue(i25)) {
                TypedArray typedArray14 = this.typedArray;
                int i26 = C4028R.styleable.background_bl_unPressed_stroke_color;
                if (typedArray14.hasValue(i26)) {
                    arrayList3.add(Integer.valueOf(R.attr.state_pressed));
                    arrayList3.add(-16842919);
                    C1499a.m603Y(this.typedArray, i25, 0, arrayList4);
                    C1499a.m603Y(this.typedArray, i26, 0, arrayList4);
                }
            }
            TypedArray typedArray15 = this.typedArray;
            int i27 = C4028R.styleable.background_bl_checkable_stroke_color;
            if (typedArray15.hasValue(i27)) {
                TypedArray typedArray16 = this.typedArray;
                int i28 = C4028R.styleable.background_bl_unCheckable_stroke_color;
                if (typedArray16.hasValue(i28)) {
                    arrayList3.add(Integer.valueOf(R.attr.state_checkable));
                    arrayList3.add(-16842911);
                    C1499a.m603Y(this.typedArray, i27, 0, arrayList4);
                    C1499a.m603Y(this.typedArray, i28, 0, arrayList4);
                }
            }
            TypedArray typedArray17 = this.typedArray;
            int i29 = C4028R.styleable.background_bl_checked_stroke_color;
            if (typedArray17.hasValue(i29)) {
                TypedArray typedArray18 = this.typedArray;
                int i30 = C4028R.styleable.background_bl_unChecked_stroke_color;
                if (typedArray18.hasValue(i30)) {
                    arrayList3.add(Integer.valueOf(R.attr.state_checked));
                    arrayList3.add(-16842912);
                    C1499a.m603Y(this.typedArray, i29, 0, arrayList4);
                    C1499a.m603Y(this.typedArray, i30, 0, arrayList4);
                }
            }
            TypedArray typedArray19 = this.typedArray;
            int i31 = C4028R.styleable.background_bl_enabled_stroke_color;
            if (typedArray19.hasValue(i31)) {
                TypedArray typedArray20 = this.typedArray;
                int i32 = C4028R.styleable.background_bl_unEnabled_stroke_color;
                if (typedArray20.hasValue(i32)) {
                    arrayList3.add(Integer.valueOf(R.attr.state_enabled));
                    arrayList3.add(-16842910);
                    C1499a.m603Y(this.typedArray, i31, 0, arrayList4);
                    C1499a.m603Y(this.typedArray, i32, 0, arrayList4);
                }
            }
            TypedArray typedArray21 = this.typedArray;
            int i33 = C4028R.styleable.background_bl_selected_stroke_color;
            if (typedArray21.hasValue(i33)) {
                TypedArray typedArray22 = this.typedArray;
                int i34 = C4028R.styleable.background_bl_unSelected_stroke_color;
                if (typedArray22.hasValue(i34)) {
                    arrayList3.add(Integer.valueOf(R.attr.state_selected));
                    arrayList3.add(-16842913);
                    C1499a.m603Y(this.typedArray, i33, 0, arrayList4);
                    C1499a.m603Y(this.typedArray, i34, 0, arrayList4);
                }
            }
            TypedArray typedArray23 = this.typedArray;
            int i35 = C4028R.styleable.background_bl_focused_stroke_color;
            if (typedArray23.hasValue(i35)) {
                TypedArray typedArray24 = this.typedArray;
                int i36 = C4028R.styleable.background_bl_unFocused_stroke_color;
                if (typedArray24.hasValue(i36)) {
                    arrayList3.add(Integer.valueOf(R.attr.state_focused));
                    arrayList3.add(-16842908);
                    C1499a.m603Y(this.typedArray, i35, 0, arrayList4);
                    C1499a.m603Y(this.typedArray, i36, 0, arrayList4);
                }
            }
            if (arrayList3.size() > 0) {
                int[][] iArr3 = new int[arrayList3.size()][];
                int[] iArr4 = new int[arrayList3.size()];
                Iterator it2 = arrayList3.iterator();
                int i37 = 0;
                while (it2.hasNext()) {
                    iArr3[i37] = new int[]{((Integer) it2.next()).intValue()};
                    iArr4[i37] = ((Integer) arrayList4.get(i37)).intValue();
                    i37++;
                }
                gradientDrawable.setStroke((int) f5, new ColorStateList(iArr3, iArr4), f6, f7);
            } else if (this.typedArray.hasValue(C4028R.styleable.background_bl_stroke_color)) {
                gradientDrawable.setStroke((int) f5, i5, f6, f7);
            }
        }
        if (this.typedArray.hasValue(C4028R.styleable.background_bl_gradient_centerX) && this.typedArray.hasValue(C4028R.styleable.background_bl_gradient_centerY)) {
            gradientDrawable.setGradientCenter(f11, f12);
        }
        if (this.typedArray.hasValue(C4028R.styleable.background_bl_gradient_startColor) && this.typedArray.hasValue(C4028R.styleable.background_bl_gradient_endColor)) {
            gradientDrawable.setColors(this.typedArray.hasValue(C4028R.styleable.background_bl_gradient_centerColor) ? new int[]{i6, i9, i7} : new int[]{i6, i7});
        }
        if (i8 == 0 && this.typedArray.hasValue(C4028R.styleable.background_bl_gradient_angle)) {
            int i38 = i10 % 360;
            if (i38 % 45 != 0) {
                throw new XmlPullParserException(this.typedArray.getPositionDescription() + "<gradient> tag requires 'angle' attribute to be a multiple of 45");
            }
            GradientDrawable.Orientation orientation = GradientDrawable.Orientation.LEFT_RIGHT;
            if (i38 != 0) {
                if (i38 == 45) {
                    orientation = GradientDrawable.Orientation.BL_TR;
                } else if (i38 == 90) {
                    orientation = GradientDrawable.Orientation.BOTTOM_TOP;
                } else if (i38 == 135) {
                    orientation = GradientDrawable.Orientation.BR_TL;
                } else if (i38 == 180) {
                    orientation = GradientDrawable.Orientation.RIGHT_LEFT;
                } else if (i38 == 225) {
                    orientation = GradientDrawable.Orientation.TR_BL;
                } else if (i38 == 270) {
                    orientation = GradientDrawable.Orientation.TOP_BOTTOM;
                } else if (i38 == 315) {
                    orientation = GradientDrawable.Orientation.TL_BR;
                }
            }
            gradientDrawable.setOrientation(orientation);
        }
        if (this.typedArray.hasValue(C4028R.styleable.background_bl_padding_left) && this.typedArray.hasValue(C4028R.styleable.background_bl_padding_top) && this.typedArray.hasValue(C4028R.styleable.background_bl_padding_right) && this.typedArray.hasValue(C4028R.styleable.background_bl_padding_bottom)) {
            if (Build.VERSION.SDK_INT >= 29) {
                gradientDrawable.setPadding(rect.left, rect.top, rect.right, rect.bottom);
            } else {
                try {
                    Field declaredField = gradientDrawable.getClass().getDeclaredField("mPadding");
                    declaredField.setAccessible(true);
                    declaredField.set(gradientDrawable, rect);
                } catch (IllegalAccessException e2) {
                    e2.printStackTrace();
                } catch (NoSuchFieldException e3) {
                    e3.printStackTrace();
                }
            }
        }
        return gradientDrawable;
    }
}
