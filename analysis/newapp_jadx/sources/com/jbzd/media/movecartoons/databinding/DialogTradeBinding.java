package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogTradeBinding implements ViewBinding {

    @NonNull
    public final GradientRoundCornerButton btnSubmitAichangefaceVideo;

    @NonNull
    public final AppCompatEditText etMemo;

    @NonNull
    public final ImageView ivClose;

    @NonNull
    public final RadioButton rbCancel;

    @NonNull
    public final RadioButton rbDone;

    @NonNull
    public final RadioGroup rgTrade;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tvContent;

    @NonNull
    public final TextView tvMemo;

    @NonNull
    public final TextView tvTitle;

    @NonNull
    public final View view2;

    private DialogTradeBinding(@NonNull FrameLayout frameLayout, @NonNull GradientRoundCornerButton gradientRoundCornerButton, @NonNull AppCompatEditText appCompatEditText, @NonNull ImageView imageView, @NonNull RadioButton radioButton, @NonNull RadioButton radioButton2, @NonNull RadioGroup radioGroup, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull View view) {
        this.rootView = frameLayout;
        this.btnSubmitAichangefaceVideo = gradientRoundCornerButton;
        this.etMemo = appCompatEditText;
        this.ivClose = imageView;
        this.rbCancel = radioButton;
        this.rbDone = radioButton2;
        this.rgTrade = radioGroup;
        this.tvContent = textView;
        this.tvMemo = textView2;
        this.tvTitle = textView3;
        this.view2 = view;
    }

    @NonNull
    public static DialogTradeBinding bind(@NonNull View view) {
        int i2 = R.id.btn_submit_aichangeface_video;
        GradientRoundCornerButton gradientRoundCornerButton = (GradientRoundCornerButton) view.findViewById(R.id.btn_submit_aichangeface_video);
        if (gradientRoundCornerButton != null) {
            i2 = R.id.et_memo;
            AppCompatEditText appCompatEditText = (AppCompatEditText) view.findViewById(R.id.et_memo);
            if (appCompatEditText != null) {
                i2 = R.id.iv_close;
                ImageView imageView = (ImageView) view.findViewById(R.id.iv_close);
                if (imageView != null) {
                    i2 = R.id.rb_cancel;
                    RadioButton radioButton = (RadioButton) view.findViewById(R.id.rb_cancel);
                    if (radioButton != null) {
                        i2 = R.id.rb_done;
                        RadioButton radioButton2 = (RadioButton) view.findViewById(R.id.rb_done);
                        if (radioButton2 != null) {
                            i2 = R.id.rg_trade;
                            RadioGroup radioGroup = (RadioGroup) view.findViewById(R.id.rg_trade);
                            if (radioGroup != null) {
                                i2 = R.id.tv_content;
                                TextView textView = (TextView) view.findViewById(R.id.tv_content);
                                if (textView != null) {
                                    i2 = R.id.tv_memo;
                                    TextView textView2 = (TextView) view.findViewById(R.id.tv_memo);
                                    if (textView2 != null) {
                                        i2 = R.id.tv_title;
                                        TextView textView3 = (TextView) view.findViewById(R.id.tv_title);
                                        if (textView3 != null) {
                                            i2 = R.id.view2;
                                            View findViewById = view.findViewById(R.id.view2);
                                            if (findViewById != null) {
                                                return new DialogTradeBinding((FrameLayout) view, gradientRoundCornerButton, appCompatEditText, imageView, radioButton, radioButton2, radioGroup, textView, textView2, textView3, findViewById);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogTradeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogTradeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_trade, viewGroup, false);
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
