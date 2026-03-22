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
public final class HomeVideoPlayerBinding implements ViewBinding {

    @NonNull
    public final ImageView back;

    @NonNull
    public final ProgressBar bottomProgressbar;

    @NonNull
    public final ImageView btnStop;

    @NonNull
    public final ImageView btnVoice;

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
    public final ImageView lockScreen;

    @NonNull
    public final ImageView player;

    @NonNull
    public final SeekBar progress;

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

    private HomeVideoPlayerBinding(@NonNull RelativeLayout relativeLayout, @NonNull ImageView imageView, @NonNull ProgressBar progressBar, @NonNull ImageView imageView2, @NonNull ImageView imageView3, @NonNull TextView textView, @NonNull ImageView imageView4, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull ENDownloadView eNDownloadView, @NonNull ImageView imageView5, @NonNull ImageView imageView6, @NonNull SeekBar seekBar, @NonNull ImageView imageView7, @NonNull FrameLayout frameLayout, @NonNull RelativeLayout relativeLayout2, @NonNull ImageView imageView8, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = relativeLayout;
        this.back = imageView;
        this.bottomProgressbar = progressBar;
        this.btnStop = imageView2;
        this.btnVoice = imageView3;
        this.current = textView;
        this.fullscreen = imageView4;
        this.layoutBottom = linearLayout;
        this.layoutTop = linearLayout2;
        this.loading = eNDownloadView;
        this.lockScreen = imageView5;
        this.player = imageView6;
        this.progress = seekBar;
        this.smallClose = imageView7;
        this.surfaceContainer = frameLayout;
        this.thumb = relativeLayout2;
        this.thumbImage = imageView8;
        this.title = textView2;
        this.total = textView3;
    }

    @NonNull
    public static HomeVideoPlayerBinding bind(@NonNull View view) {
        int i2 = R.id.back;
        ImageView imageView = (ImageView) view.findViewById(R.id.back);
        if (imageView != null) {
            i2 = R.id.bottom_progressbar;
            ProgressBar progressBar = (ProgressBar) view.findViewById(R.id.bottom_progressbar);
            if (progressBar != null) {
                i2 = R.id.btn_stop;
                ImageView imageView2 = (ImageView) view.findViewById(R.id.btn_stop);
                if (imageView2 != null) {
                    i2 = R.id.btn_voice;
                    ImageView imageView3 = (ImageView) view.findViewById(R.id.btn_voice);
                    if (imageView3 != null) {
                        i2 = R.id.current;
                        TextView textView = (TextView) view.findViewById(R.id.current);
                        if (textView != null) {
                            i2 = R.id.fullscreen;
                            ImageView imageView4 = (ImageView) view.findViewById(R.id.fullscreen);
                            if (imageView4 != null) {
                                i2 = R.id.layout_bottom;
                                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.layout_bottom);
                                if (linearLayout != null) {
                                    i2 = R.id.layout_top;
                                    LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.layout_top);
                                    if (linearLayout2 != null) {
                                        i2 = R.id.loading;
                                        ENDownloadView eNDownloadView = (ENDownloadView) view.findViewById(R.id.loading);
                                        if (eNDownloadView != null) {
                                            i2 = R.id.lock_screen;
                                            ImageView imageView5 = (ImageView) view.findViewById(R.id.lock_screen);
                                            if (imageView5 != null) {
                                                i2 = R.id.player;
                                                ImageView imageView6 = (ImageView) view.findViewById(R.id.player);
                                                if (imageView6 != null) {
                                                    i2 = R.id.progress;
                                                    SeekBar seekBar = (SeekBar) view.findViewById(R.id.progress);
                                                    if (seekBar != null) {
                                                        i2 = R.id.small_close;
                                                        ImageView imageView7 = (ImageView) view.findViewById(R.id.small_close);
                                                        if (imageView7 != null) {
                                                            i2 = R.id.surface_container;
                                                            FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.surface_container);
                                                            if (frameLayout != null) {
                                                                i2 = R.id.thumb;
                                                                RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.thumb);
                                                                if (relativeLayout != null) {
                                                                    i2 = R.id.thumbImage;
                                                                    ImageView imageView8 = (ImageView) view.findViewById(R.id.thumbImage);
                                                                    if (imageView8 != null) {
                                                                        i2 = R.id.title;
                                                                        TextView textView2 = (TextView) view.findViewById(R.id.title);
                                                                        if (textView2 != null) {
                                                                            i2 = R.id.total;
                                                                            TextView textView3 = (TextView) view.findViewById(R.id.total);
                                                                            if (textView3 != null) {
                                                                                return new HomeVideoPlayerBinding((RelativeLayout) view, imageView, progressBar, imageView2, imageView3, textView, imageView4, linearLayout, linearLayout2, eNDownloadView, imageView5, imageView6, seekBar, imageView7, frameLayout, relativeLayout, imageView8, textView2, textView3);
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
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static HomeVideoPlayerBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static HomeVideoPlayerBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.home_video_player, viewGroup, false);
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
