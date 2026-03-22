package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.ProgressButton;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActModifyNicknameBinding implements ViewBinding {

    @NonNull
    public final AppCompatEditText etContent;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final ProgressButton submit;

    @NonNull
    public final TextView tvTips;

    @NonNull
    public final TextView tvTitle;

    private ActModifyNicknameBinding(@NonNull LinearLayout linearLayout, @NonNull AppCompatEditText appCompatEditText, @NonNull ProgressButton progressButton, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = linearLayout;
        this.etContent = appCompatEditText;
        this.submit = progressButton;
        this.tvTips = textView;
        this.tvTitle = textView2;
    }

    @NonNull
    public static ActModifyNicknameBinding bind(@NonNull View view) {
        int i2 = R.id.et_content;
        AppCompatEditText appCompatEditText = (AppCompatEditText) view.findViewById(R.id.et_content);
        if (appCompatEditText != null) {
            i2 = R.id.submit;
            ProgressButton progressButton = (ProgressButton) view.findViewById(R.id.submit);
            if (progressButton != null) {
                i2 = R.id.tvTips;
                TextView textView = (TextView) view.findViewById(R.id.tvTips);
                if (textView != null) {
                    i2 = R.id.tvTitle;
                    TextView textView2 = (TextView) view.findViewById(R.id.tvTitle);
                    if (textView2 != null) {
                        return new ActModifyNicknameBinding((LinearLayout) view, appCompatEditText, progressButton, textView, textView2);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActModifyNicknameBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActModifyNicknameBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_modify_nickname, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public LinearLayout getRoot() {
        return this.rootView;
    }
}
