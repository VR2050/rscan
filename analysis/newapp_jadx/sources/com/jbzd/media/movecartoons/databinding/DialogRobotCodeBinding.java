package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogRobotCodeBinding implements ViewBinding {

    @NonNull
    public final AppCompatEditText editRobotCode;

    @NonNull
    public final ImageView ivClose;

    @NonNull
    public final ImageView ivPicVef;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tvRobotcodeChange;

    @NonNull
    public final TextView tvRobotcodeSure;

    @NonNull
    public final View view2;

    private DialogRobotCodeBinding(@NonNull FrameLayout frameLayout, @NonNull AppCompatEditText appCompatEditText, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull TextView textView, @NonNull TextView textView2, @NonNull View view) {
        this.rootView = frameLayout;
        this.editRobotCode = appCompatEditText;
        this.ivClose = imageView;
        this.ivPicVef = imageView2;
        this.tvRobotcodeChange = textView;
        this.tvRobotcodeSure = textView2;
        this.view2 = view;
    }

    @NonNull
    public static DialogRobotCodeBinding bind(@NonNull View view) {
        int i2 = R.id.edit_robot_code;
        AppCompatEditText appCompatEditText = (AppCompatEditText) view.findViewById(R.id.edit_robot_code);
        if (appCompatEditText != null) {
            i2 = R.id.iv_close;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_close);
            if (imageView != null) {
                i2 = R.id.iv_picVef;
                ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_picVef);
                if (imageView2 != null) {
                    i2 = R.id.tv_robotcode_change;
                    TextView textView = (TextView) view.findViewById(R.id.tv_robotcode_change);
                    if (textView != null) {
                        i2 = R.id.tv_robotcode_sure;
                        TextView textView2 = (TextView) view.findViewById(R.id.tv_robotcode_sure);
                        if (textView2 != null) {
                            i2 = R.id.view2;
                            View findViewById = view.findViewById(R.id.view2);
                            if (findViewById != null) {
                                return new DialogRobotCodeBinding((FrameLayout) view, appCompatEditText, imageView, imageView2, textView, textView2, findViewById);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogRobotCodeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogRobotCodeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_robot_code, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public FrameLayout getRoot() {
        return this.rootView;
    }
}
