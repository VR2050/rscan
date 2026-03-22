package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class VideoBlockTitleBinding implements ViewBinding {

    @NonNull
    public final ImageTextView btnMore;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final TextView tvTitle;

    private VideoBlockTitleBinding(@NonNull RelativeLayout relativeLayout, @NonNull ImageTextView imageTextView, @NonNull TextView textView) {
        this.rootView = relativeLayout;
        this.btnMore = imageTextView;
        this.tvTitle = textView;
    }

    @NonNull
    public static VideoBlockTitleBinding bind(@NonNull View view) {
        int i2 = R.id.btn_more;
        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.btn_more);
        if (imageTextView != null) {
            i2 = R.id.tv_title;
            TextView textView = (TextView) view.findViewById(R.id.tv_title);
            if (textView != null) {
                return new VideoBlockTitleBinding((RelativeLayout) view, imageTextView, textView);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static VideoBlockTitleBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static VideoBlockTitleBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.video_block_title, viewGroup, false);
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
