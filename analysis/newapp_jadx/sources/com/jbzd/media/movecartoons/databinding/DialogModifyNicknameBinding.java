package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.widget.ClearEditText;

/* loaded from: classes2.dex */
public final class DialogModifyNicknameBinding implements ViewBinding {

    @NonNull
    public final GradientRoundCornerButton btnSubmitAichangefaceVideo;

    @NonNull
    public final ImageView close;

    @NonNull
    public final ClearEditText etContent;

    @NonNull
    public final TextView itvNickname;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tips;

    @NonNull
    public final TextView tvCount;

    @NonNull
    public final View view2;

    private DialogModifyNicknameBinding(@NonNull FrameLayout frameLayout, @NonNull GradientRoundCornerButton gradientRoundCornerButton, @NonNull ImageView imageView, @NonNull ClearEditText clearEditText, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull View view) {
        this.rootView = frameLayout;
        this.btnSubmitAichangefaceVideo = gradientRoundCornerButton;
        this.close = imageView;
        this.etContent = clearEditText;
        this.itvNickname = textView;
        this.tips = textView2;
        this.tvCount = textView3;
        this.view2 = view;
    }

    @NonNull
    public static DialogModifyNicknameBinding bind(@NonNull View view) {
        int i2 = R.id.btn_submit_aichangeface_video;
        GradientRoundCornerButton gradientRoundCornerButton = (GradientRoundCornerButton) view.findViewById(R.id.btn_submit_aichangeface_video);
        if (gradientRoundCornerButton != null) {
            i2 = R.id.close;
            ImageView imageView = (ImageView) view.findViewById(R.id.close);
            if (imageView != null) {
                i2 = R.id.et_content;
                ClearEditText clearEditText = (ClearEditText) view.findViewById(R.id.et_content);
                if (clearEditText != null) {
                    i2 = R.id.itv_nickname;
                    TextView textView = (TextView) view.findViewById(R.id.itv_nickname);
                    if (textView != null) {
                        i2 = R.id.tips;
                        TextView textView2 = (TextView) view.findViewById(R.id.tips);
                        if (textView2 != null) {
                            i2 = R.id.tv_count;
                            TextView textView3 = (TextView) view.findViewById(R.id.tv_count);
                            if (textView3 != null) {
                                i2 = R.id.view2;
                                View findViewById = view.findViewById(R.id.view2);
                                if (findViewById != null) {
                                    return new DialogModifyNicknameBinding((FrameLayout) view, gradientRoundCornerButton, imageView, clearEditText, textView, textView2, textView3, findViewById);
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
    public static DialogModifyNicknameBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogModifyNicknameBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_modify_nickname, viewGroup, false);
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
