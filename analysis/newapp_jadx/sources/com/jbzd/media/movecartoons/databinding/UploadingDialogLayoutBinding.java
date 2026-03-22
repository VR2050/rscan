package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class UploadingDialogLayoutBinding implements ViewBinding {

    @NonNull
    public final ProgressBar progress;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final TextView tvMsg;

    @NonNull
    public final TextView tvTitle;

    private UploadingDialogLayoutBinding(@NonNull RelativeLayout relativeLayout, @NonNull ProgressBar progressBar, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = relativeLayout;
        this.progress = progressBar;
        this.tvMsg = textView;
        this.tvTitle = textView2;
    }

    @NonNull
    public static UploadingDialogLayoutBinding bind(@NonNull View view) {
        int i2 = R.id.progress;
        ProgressBar progressBar = (ProgressBar) view.findViewById(R.id.progress);
        if (progressBar != null) {
            i2 = R.id.tv_msg;
            TextView textView = (TextView) view.findViewById(R.id.tv_msg);
            if (textView != null) {
                i2 = R.id.tv_title;
                TextView textView2 = (TextView) view.findViewById(R.id.tv_title);
                if (textView2 != null) {
                    return new UploadingDialogLayoutBinding((RelativeLayout) view, progressBar, textView, textView2);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static UploadingDialogLayoutBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static UploadingDialogLayoutBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.uploading_dialog_layout, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public RelativeLayout getRoot() {
        return this.rootView;
    }
}
