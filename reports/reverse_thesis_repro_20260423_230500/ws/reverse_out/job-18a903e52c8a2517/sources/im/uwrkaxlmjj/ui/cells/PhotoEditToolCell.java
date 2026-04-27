package im.uwrkaxlmjj.ui.cells;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.text.TextUtils;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.PhotoEditorSeekBar;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
public class PhotoEditToolCell extends FrameLayout {
    private Runnable hideValueRunnable;
    private TextView nameTextView;
    private PhotoEditorSeekBar seekBar;
    private AnimatorSet valueAnimation;
    private TextView valueTextView;

    public PhotoEditToolCell(Context context) {
        super(context);
        this.hideValueRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.cells.PhotoEditToolCell.1
            @Override // java.lang.Runnable
            public void run() {
                PhotoEditToolCell.this.valueTextView.setTag(null);
                PhotoEditToolCell.this.valueAnimation = new AnimatorSet();
                PhotoEditToolCell.this.valueAnimation.playTogether(ObjectAnimator.ofFloat(PhotoEditToolCell.this.valueTextView, "alpha", 0.0f), ObjectAnimator.ofFloat(PhotoEditToolCell.this.nameTextView, "alpha", 1.0f));
                PhotoEditToolCell.this.valueAnimation.setDuration(180L);
                PhotoEditToolCell.this.valueAnimation.setInterpolator(new DecelerateInterpolator());
                PhotoEditToolCell.this.valueAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.cells.PhotoEditToolCell.1.1
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (animation.equals(PhotoEditToolCell.this.valueAnimation)) {
                            PhotoEditToolCell.this.valueAnimation = null;
                        }
                    }
                });
                PhotoEditToolCell.this.valueAnimation.start();
            }
        };
        TextView textView = new TextView(context);
        this.nameTextView = textView;
        textView.setGravity(5);
        this.nameTextView.setTextColor(-1);
        this.nameTextView.setTextSize(1, 12.0f);
        this.nameTextView.setMaxLines(1);
        this.nameTextView.setSingleLine(true);
        this.nameTextView.setEllipsize(TextUtils.TruncateAt.END);
        addView(this.nameTextView, LayoutHelper.createFrame(80.0f, -2.0f, 19, 0.0f, 0.0f, 0.0f, 0.0f));
        TextView textView2 = new TextView(context);
        this.valueTextView = textView2;
        textView2.setTextColor(-9649153);
        this.valueTextView.setTextSize(1, 12.0f);
        this.valueTextView.setGravity(5);
        this.valueTextView.setSingleLine(true);
        addView(this.valueTextView, LayoutHelper.createFrame(80.0f, -2.0f, 19, 0.0f, 0.0f, 0.0f, 0.0f));
        PhotoEditorSeekBar photoEditorSeekBar = new PhotoEditorSeekBar(context);
        this.seekBar = photoEditorSeekBar;
        addView(photoEditorSeekBar, LayoutHelper.createFrame(-1.0f, 40.0f, 19, 96.0f, 0.0f, 24.0f, 0.0f));
    }

    public void setSeekBarDelegate(final PhotoEditorSeekBar.PhotoEditorSeekBarDelegate photoEditorSeekBarDelegate) {
        this.seekBar.setDelegate(new PhotoEditorSeekBar.PhotoEditorSeekBarDelegate() { // from class: im.uwrkaxlmjj.ui.cells.PhotoEditToolCell.2
            @Override // im.uwrkaxlmjj.ui.components.PhotoEditorSeekBar.PhotoEditorSeekBarDelegate
            public void onProgressChanged(int i, int progress) {
                photoEditorSeekBarDelegate.onProgressChanged(i, progress);
                if (progress > 0) {
                    PhotoEditToolCell.this.valueTextView.setText(Marker.ANY_NON_NULL_MARKER + progress);
                } else {
                    PhotoEditToolCell.this.valueTextView.setText("" + progress);
                }
                if (PhotoEditToolCell.this.valueTextView.getTag() == null) {
                    if (PhotoEditToolCell.this.valueAnimation != null) {
                        PhotoEditToolCell.this.valueAnimation.cancel();
                    }
                    PhotoEditToolCell.this.valueTextView.setTag(1);
                    PhotoEditToolCell.this.valueAnimation = new AnimatorSet();
                    PhotoEditToolCell.this.valueAnimation.playTogether(ObjectAnimator.ofFloat(PhotoEditToolCell.this.valueTextView, "alpha", 1.0f), ObjectAnimator.ofFloat(PhotoEditToolCell.this.nameTextView, "alpha", 0.0f));
                    PhotoEditToolCell.this.valueAnimation.setDuration(180L);
                    PhotoEditToolCell.this.valueAnimation.setInterpolator(new DecelerateInterpolator());
                    PhotoEditToolCell.this.valueAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.cells.PhotoEditToolCell.2.1
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            AndroidUtilities.runOnUIThread(PhotoEditToolCell.this.hideValueRunnable, 1000L);
                        }
                    });
                    PhotoEditToolCell.this.valueAnimation.start();
                    return;
                }
                AndroidUtilities.cancelRunOnUIThread(PhotoEditToolCell.this.hideValueRunnable);
                AndroidUtilities.runOnUIThread(PhotoEditToolCell.this.hideValueRunnable, 1000L);
            }
        });
    }

    @Override // android.view.View
    public void setTag(Object tag) {
        super.setTag(tag);
        this.seekBar.setTag(tag);
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(40.0f), 1073741824));
    }

    public void setIconAndTextAndValue(String text, float value, int min, int max) {
        AnimatorSet animatorSet = this.valueAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.valueAnimation = null;
        }
        AndroidUtilities.cancelRunOnUIThread(this.hideValueRunnable);
        this.valueTextView.setTag(null);
        this.nameTextView.setText(text.substring(0, 1).toUpperCase() + text.substring(1).toLowerCase());
        if (value > 0.0f) {
            this.valueTextView.setText(Marker.ANY_NON_NULL_MARKER + ((int) value));
        } else {
            this.valueTextView.setText("" + ((int) value));
        }
        this.valueTextView.setAlpha(0.0f);
        this.nameTextView.setAlpha(1.0f);
        this.seekBar.setMinMax(min, max);
        this.seekBar.setProgress((int) value, false);
    }
}
