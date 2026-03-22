package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActDownloadBinding implements ViewBinding {

    @NonNull
    public final RelativeLayout btnAll;

    @NonNull
    public final RelativeLayout btnCancel;

    @NonNull
    public final TextView btnDel;

    @NonNull
    public final FrameLayout frContainer;

    @NonNull
    public final TextView ivTitleLeftIcon;

    @NonNull
    public final RelativeLayout rlEdit;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvAll;

    private ActDownloadBinding(@NonNull LinearLayout linearLayout, @NonNull RelativeLayout relativeLayout, @NonNull RelativeLayout relativeLayout2, @NonNull TextView textView, @NonNull FrameLayout frameLayout, @NonNull TextView textView2, @NonNull RelativeLayout relativeLayout3, @NonNull TextView textView3) {
        this.rootView = linearLayout;
        this.btnAll = relativeLayout;
        this.btnCancel = relativeLayout2;
        this.btnDel = textView;
        this.frContainer = frameLayout;
        this.ivTitleLeftIcon = textView2;
        this.rlEdit = relativeLayout3;
        this.tvAll = textView3;
    }

    @NonNull
    public static ActDownloadBinding bind(@NonNull View view) {
        int i2 = R.id.btnAll;
        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.btnAll);
        if (relativeLayout != null) {
            i2 = R.id.btnCancel;
            RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.btnCancel);
            if (relativeLayout2 != null) {
                i2 = R.id.btnDel;
                TextView textView = (TextView) view.findViewById(R.id.btnDel);
                if (textView != null) {
                    i2 = R.id.fr_container;
                    FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.fr_container);
                    if (frameLayout != null) {
                        i2 = R.id.iv_titleLeftIcon;
                        TextView textView2 = (TextView) view.findViewById(R.id.iv_titleLeftIcon);
                        if (textView2 != null) {
                            i2 = R.id.rlEdit;
                            RelativeLayout relativeLayout3 = (RelativeLayout) view.findViewById(R.id.rlEdit);
                            if (relativeLayout3 != null) {
                                i2 = R.id.tvAll;
                                TextView textView3 = (TextView) view.findViewById(R.id.tvAll);
                                if (textView3 != null) {
                                    return new ActDownloadBinding((LinearLayout) view, relativeLayout, relativeLayout2, textView, frameLayout, textView2, relativeLayout3, textView3);
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
    public static ActDownloadBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActDownloadBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_download, viewGroup, false);
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
