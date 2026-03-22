package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import android.widget.SeekBar;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;
import moe.codeest.enviews.ENDownloadView;

/* loaded from: classes2.dex */
public final class ListVideoPlayerBinding implements ViewBinding {

    @NonNull
    public final ImageView back;

    @NonNull
    public final ProgressBar bottomProgressbar;

    @NonNull
    public final ImageView btnStop;

    @NonNull
    public final TextView current;

    @NonNull
    public final ImageView fullscreen;

    @NonNull
    public final LinearLayout layoutBottom;

    @NonNull
    public final LinearLayout layoutTop;

    @NonNull
    public final ENDownloadView loading;

    @NonNull
    public final ImageView player;

    @NonNull
    public final SeekBar progress;

    @NonNull
    public final RelativeLayout rlLayout;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final ImageView smallClose;

    @NonNull
    public final FrameLayout surfaceContainer;

    @NonNull
    public final RelativeLayout thumb;

    @NonNull
    public final ImageView thumbImage;

    @NonNull
    public final TextView title;

    @NonNull
    public final TextView total;

    private ListVideoPlayerBinding(@NonNull RelativeLayout relativeLayout, @NonNull ImageView imageView, @NonNull ProgressBar progressBar, @NonNull ImageView imageView2, @NonNull TextView textView, @NonNull ImageView imageView3, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull ENDownloadView eNDownloadView, @NonNull ImageView imageView4, @NonNull SeekBar seekBar, @NonNull RelativeLayout relativeLayout2, @NonNull ImageView imageView5, @NonNull FrameLayout frameLayout, @NonNull RelativeLayout relativeLayout3, @NonNull ImageView imageView6, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = relativeLayout;
        this.back = imageView;
        this.bottomProgressbar = progressBar;
        this.btnStop = imageView2;
        this.current = textView;
        this.fullscreen = imageView3;
        this.layoutBottom = linearLayout;
        this.layoutTop = linearLayout2;
        this.loading = eNDownloadView;
        this.player = imageView4;
        this.progress = seekBar;
        this.rlLayout = relativeLayout2;
        this.smallClose = imageView5;
        this.surfaceContainer = frameLayout;
        this.thumb = relativeLayout3;
        this.thumbImage = imageView6;
        this.title = textView2;
        this.total = textView3;
    }

    @NonNull
    public static ListVideoPlayerBinding bind(@NonNull View view) {
        int i2 = R.id.back;
        ImageView imageView = (ImageView) view.findViewById(R.id.back);
        if (imageView != null) {
            i2 = R.id.bottom_progressbar;
            ProgressBar progressBar = (ProgressBar) view.findViewById(R.id.bottom_progressbar);
            if (progressBar != null) {
                i2 = R.id.btn_stop;
                ImageView imageView2 = (ImageView) view.findViewById(R.id.btn_stop);
                if (imageView2 != null) {
                    i2 = R.id.current;
                    TextView textView = (TextView) view.findViewById(R.id.current);
                    if (textView != null) {
                        i2 = R.id.fullscreen;
                        ImageView imageView3 = (ImageView) view.findViewById(R.id.fullscreen);
                        if (imageView3 != null) {
                            i2 = R.id.layout_bottom;
                            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.layout_bottom);
                            if (linearLayout != null) {
                                i2 = R.id.layout_top;
                                LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.layout_top);
                                if (linearLayout2 != null) {
                                    i2 = R.id.loading;
                                    ENDownloadView eNDownloadView = (ENDownloadView) view.findViewById(R.id.loading);
                                    if (eNDownloadView != null) {
                                        i2 = R.id.player;
                                        ImageView imageView4 = (ImageView) view.findViewById(R.id.player);
                                        if (imageView4 != null) {
                                            i2 = R.id.progress;
                                            SeekBar seekBar = (SeekBar) view.findViewById(R.id.progress);
                                            if (seekBar != null) {
                                                RelativeLayout relativeLayout = (RelativeLayout) view;
                                                i2 = R.id.small_close;
                                                ImageView imageView5 = (ImageView) view.findViewById(R.id.small_close);
                                                if (imageView5 != null) {
                                                    i2 = R.id.surface_container;
                                                    FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.surface_container);
                                                    if (frameLayout != null) {
                                                        i2 = R.id.thumb;
                                                        RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.thumb);
                                                        if (relativeLayout2 != null) {
                                                            i2 = R.id.thumbImage;
                                                            ImageView imageView6 = (ImageView) view.findViewById(R.id.thumbImage);
                                                            if (imageView6 != null) {
                                                                i2 = R.id.title;
                                                                TextView textView2 = (TextView) view.findViewById(R.id.title);
                                                                if (textView2 != null) {
                                                                    i2 = R.id.total;
                                                                    TextView textView3 = (TextView) view.findViewById(R.id.total);
                                                                    if (textView3 != null) {
                                                                        return new ListVideoPlayerBinding(relativeLayout, imageView, progressBar, imageView2, textView, imageView3, linearLayout, linearLayout2, eNDownloadView, imageView4, seekBar, relativeLayout, imageView5, frameLayout, relativeLayout2, imageView6, textView2, textView3);
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
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ListVideoPlayerBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ListVideoPlayerBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.list_video_player, viewGroup, false);
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
