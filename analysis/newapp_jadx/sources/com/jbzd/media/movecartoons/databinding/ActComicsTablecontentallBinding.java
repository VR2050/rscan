package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActComicsTablecontentallBinding implements ViewBinding {

    @NonNull
    public final LinearLayout lLayoutBg;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvComicsChapterall;

    private ActComicsTablecontentallBinding(@NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull RecyclerView recyclerView) {
        this.rootView = linearLayout;
        this.lLayoutBg = linearLayout2;
        this.rvComicsChapterall = recyclerView;
    }

    @NonNull
    public static ActComicsTablecontentallBinding bind(@NonNull View view) {
        LinearLayout linearLayout = (LinearLayout) view;
        RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_comics_chapterall);
        if (recyclerView != null) {
            return new ActComicsTablecontentallBinding((LinearLayout) view, linearLayout, recyclerView);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.rv_comics_chapterall)));
    }

    @NonNull
    public static ActComicsTablecontentallBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActComicsTablecontentallBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_comics_tablecontentall, viewGroup, false);
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
