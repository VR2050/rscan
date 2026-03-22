package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RadioGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.MyRadioButton;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ViewCanvasTab2Binding implements ViewBinding {

    @NonNull
    public final MyRadioButton radCanvasGroup;

    @NonNull
    public final MyRadioButton radCanvasLong;

    @NonNull
    public final MyRadioButton radCanvasShort;

    @NonNull
    public final RadioGroup rgCanvas;

    @NonNull
    private final RadioGroup rootView;

    private ViewCanvasTab2Binding(@NonNull RadioGroup radioGroup, @NonNull MyRadioButton myRadioButton, @NonNull MyRadioButton myRadioButton2, @NonNull MyRadioButton myRadioButton3, @NonNull RadioGroup radioGroup2) {
        this.rootView = radioGroup;
        this.radCanvasGroup = myRadioButton;
        this.radCanvasLong = myRadioButton2;
        this.radCanvasShort = myRadioButton3;
        this.rgCanvas = radioGroup2;
    }

    @NonNull
    public static ViewCanvasTab2Binding bind(@NonNull View view) {
        int i2 = R.id.rad_canvas_group;
        MyRadioButton myRadioButton = (MyRadioButton) view.findViewById(R.id.rad_canvas_group);
        if (myRadioButton != null) {
            i2 = R.id.rad_canvas_long;
            MyRadioButton myRadioButton2 = (MyRadioButton) view.findViewById(R.id.rad_canvas_long);
            if (myRadioButton2 != null) {
                i2 = R.id.rad_canvas_short;
                MyRadioButton myRadioButton3 = (MyRadioButton) view.findViewById(R.id.rad_canvas_short);
                if (myRadioButton3 != null) {
                    RadioGroup radioGroup = (RadioGroup) view;
                    return new ViewCanvasTab2Binding(radioGroup, myRadioButton, myRadioButton2, myRadioButton3, radioGroup);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ViewCanvasTab2Binding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ViewCanvasTab2Binding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.view_canvas_tab2, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public RadioGroup getRoot() {
        return this.rootView;
    }
}
