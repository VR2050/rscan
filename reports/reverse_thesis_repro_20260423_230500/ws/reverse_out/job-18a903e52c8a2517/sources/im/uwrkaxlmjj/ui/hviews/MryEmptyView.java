package im.uwrkaxlmjj.ui.hviews;

import android.content.Context;
import android.os.Build;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class MryEmptyView extends FrameLayout {
    public static final int STATUS_EMPTY_DATA = 4;
    public static final int STATUS_LOADING = 1;
    public static final int STATUS_LOAD_ERROR = 3;
    public static final int STATUS_LOAD_SUCCESS = 2;
    private MryRoundButton mBtn;
    protected int mCurrentStatus;
    private CharSequence mEmptyBtnText;
    private View mEmptyParent;
    private int mEmptyResId;
    private CharSequence mEmptyText;
    private CharSequence mErrorBtnText;
    private int mErrorResId;
    private CharSequence mErrorText;
    protected boolean mIsEmpty;
    private ImageView mIv;
    protected OnEmptyOrErrorClickListener mOEmptyClickListener;
    private RadialProgressView mProgressBar;
    private MryTextView mTextView;
    protected ViewGroup mWrapper;

    public interface OnEmptyOrErrorClickListener {
        boolean onEmptyViewButtonClick(boolean z);
    }

    public MryEmptyView(Context context) {
        this(context, null);
    }

    public MryEmptyView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public MryEmptyView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(context);
    }

    protected void init(Context context) {
        setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        setLayoutParams(new ViewGroup.LayoutParams(-1, -1));
        RadialProgressView radialProgressView = new RadialProgressView(context);
        this.mProgressBar = radialProgressView;
        radialProgressView.setSize(AndroidUtilities.dp(28.0f));
        this.mProgressBar.setProgressColor(Theme.getColor(Theme.key_chat_serviceText));
        this.mProgressBar.setBackgroundResource(R.drawable.system_loader);
        this.mProgressBar.getBackground().setColorFilter(Theme.colorFilter);
        addView(this.mProgressBar, LayoutHelper.createFrame(36, 36, 17));
        LinearLayout linearLayout = new LinearLayout(context);
        this.mEmptyParent = linearLayout;
        linearLayout.setOrientation(1);
        this.mEmptyParent.setPadding(AndroidUtilities.dp(40.0f), 0, AndroidUtilities.dp(40.0f), 0);
        this.mEmptyResId = R.id.img_empty_default;
        this.mErrorResId = R.id.img_emtpy_error_default;
        this.mEmptyText = LocaleController.getString("NoData", R.string.NoData);
        this.mErrorText = LocaleController.getString("LoadDataErrorDefault", R.string.LoadDataErrorDefault);
        this.mErrorBtnText = LocaleController.getString("ClickRetry", R.string.ClickRetry);
        ImageView imageView = new ImageView(context);
        this.mIv = imageView;
        ((LinearLayout) this.mEmptyParent).addView(imageView, LayoutHelper.createLinear(100, 100, 17));
        MryTextView mryTextView = new MryTextView(context);
        this.mTextView = mryTextView;
        mryTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText8));
        this.mTextView.setLineSpacing(AndroidUtilities.dp(5.0f), 1.0f);
        this.mTextView.setGravity(17);
        ((LinearLayout) this.mEmptyParent).addView(this.mTextView, LayoutHelper.createLinear(-2, -2, 17, 0, AndroidUtilities.dp(5.0f), 0, 0));
        MryRoundButton mryRoundButton = new MryRoundButton(context);
        this.mBtn = mryRoundButton;
        mryRoundButton.setPrimaryRadiusAdjustBoundsStrokeStyle();
        ((LinearLayout) this.mEmptyParent).addView(this.mBtn, LayoutHelper.createLinear(-2, -2, 17, 0, AndroidUtilities.dp(5.0f), 0, 0));
        this.mEmptyParent.setVisibility(8);
        addView(this.mEmptyParent, LayoutHelper.createFrame(-2, -2, 17));
    }

    public MryEmptyView attach(BaseFragment fragment) {
        attach((ViewGroup) fragment.getFragmentView());
        return this;
    }

    public MryEmptyView attach(ViewGroup viewGroup) {
        this.mWrapper = viewGroup;
        return this;
    }

    public void showLoading() {
        this.mIsEmpty = false;
        showStatus(1);
    }

    public void showContent() {
        this.mIsEmpty = false;
        showStatus(2);
    }

    public void showEmpty() {
        this.mIsEmpty = true;
        showStatus(4);
    }

    public void showError(CharSequence errorMsg) {
        this.mIsEmpty = false;
        setErrorText(errorMsg);
        showStatus(3);
    }

    public void showErrorDefault() {
        this.mIsEmpty = false;
        setErrorBtnText(LocaleController.getString("ClickRetry", R.string.ClickRetry));
        setErrorText(LocaleController.getString("LoadDataErrorDefault", R.string.LoadDataErrorDefault));
        showStatus(3);
    }

    public void showStatus(final int status) {
        int i = this.mCurrentStatus;
        if (i == status) {
            showViewByStatus(i);
        } else {
            this.mCurrentStatus = status;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hviews.-$$Lambda$MryEmptyView$bugjF1SkwEBzzDaVWsuPmDgWL9E
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$showStatus$0$MryEmptyView(status);
                }
            });
        }
    }

    public /* synthetic */ void lambda$showStatus$0$MryEmptyView(int status) {
        try {
            if (this.mWrapper != null) {
                if (this.mWrapper.indexOfChild(this) < 0) {
                    if (Build.VERSION.SDK_INT >= 21) {
                        setElevation(Float.MAX_VALUE);
                    }
                    ViewGroup.LayoutParams lp = getLayoutParams();
                    if (lp != null) {
                        lp.width = -1;
                        lp.height = -1;
                        setLayoutParams(lp);
                    }
                    this.mWrapper.addView(this);
                } else if (this.mWrapper.indexOfChild(this) != this.mWrapper.getChildCount() - 1) {
                    bringToFront();
                } else if (2 == status) {
                    this.mWrapper.removeView(this);
                }
            }
            showViewByStatus(this.mCurrentStatus);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void showViewByStatus(final int status) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hviews.-$$Lambda$MryEmptyView$XsEI-npsidpyN6pMMJROLEcEE8w
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$showViewByStatus$4$MryEmptyView(status);
            }
        });
    }

    public /* synthetic */ void lambda$showViewByStatus$4$MryEmptyView(int status) {
        if (status == 1) {
            this.mEmptyParent.setVisibility(8);
            this.mProgressBar.setVisibility(0);
            setVisibility(0);
            return;
        }
        if (status == 2) {
            setVisibility(8);
            return;
        }
        if (status == 3) {
            this.mProgressBar.setVisibility(8);
            if (this.mErrorText == null) {
                this.mTextView.setVisibility(8);
            } else {
                this.mTextView.setVisibility(0);
                this.mTextView.setText(this.mErrorText);
            }
            if (this.mErrorBtnText == null) {
                this.mBtn.setVisibility(8);
            } else {
                this.mBtn.setVisibility(0);
                this.mBtn.setText(this.mErrorBtnText);
                this.mBtn.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hviews.-$$Lambda$MryEmptyView$iaYOgdvN191xbq3UFrM1fRglpvk
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$null$3$MryEmptyView(view);
                    }
                });
            }
            this.mEmptyParent.setVisibility(0);
            this.mIv.setVisibility(0);
            this.mIv.setImageResource(this.mErrorResId);
            setOnClickListener(null);
            setVisibility(0);
            return;
        }
        if (status == 4) {
            this.mProgressBar.setVisibility(8);
            if (this.mEmptyText == null) {
                this.mTextView.setVisibility(8);
            } else {
                this.mTextView.setVisibility(0);
                this.mTextView.setText(this.mEmptyText);
            }
            if (this.mEmptyBtnText == null) {
                this.mBtn.setVisibility(8);
                if (this.mOEmptyClickListener != null) {
                    setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hviews.-$$Lambda$MryEmptyView$xlGe2N0mz3Bmcyi_5SBWDg3lfrs
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            this.f$0.lambda$null$1$MryEmptyView(view);
                        }
                    });
                }
            } else {
                this.mBtn.setVisibility(0);
                this.mBtn.setText(this.mEmptyBtnText);
                this.mBtn.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hviews.-$$Lambda$MryEmptyView$CLyOXXgaPax254iWwqb1M7hfrbw
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$null$2$MryEmptyView(view);
                    }
                });
            }
            this.mEmptyParent.setVisibility(0);
            this.mIv.setImageResource(this.mEmptyResId);
            setVisibility(0);
        }
    }

    public /* synthetic */ void lambda$null$1$MryEmptyView(View v) {
        OnEmptyOrErrorClickListener onEmptyOrErrorClickListener = this.mOEmptyClickListener;
        if (onEmptyOrErrorClickListener != null) {
            onEmptyOrErrorClickListener.onEmptyViewButtonClick(true);
        }
    }

    public /* synthetic */ void lambda$null$2$MryEmptyView(View v) {
        OnEmptyOrErrorClickListener onEmptyOrErrorClickListener = this.mOEmptyClickListener;
        if (onEmptyOrErrorClickListener != null) {
            onEmptyOrErrorClickListener.onEmptyViewButtonClick(true);
        }
    }

    public /* synthetic */ void lambda$null$3$MryEmptyView(View v) {
        OnEmptyOrErrorClickListener onEmptyOrErrorClickListener = this.mOEmptyClickListener;
        if (onEmptyOrErrorClickListener != null) {
            onEmptyOrErrorClickListener.onEmptyViewButtonClick(false);
        }
    }

    public void setEmptyResId(int emptyResId) {
        this.mEmptyResId = emptyResId;
    }

    public void setEmptyText(CharSequence emptyText) {
        this.mEmptyText = emptyText;
    }

    public void setErrorResId(int errorResId) {
        this.mErrorResId = errorResId;
    }

    public void setErrorText(CharSequence errorText) {
        this.mErrorText = errorText;
    }

    public void setErrorBtnText(CharSequence errorBtnText) {
        this.mErrorBtnText = errorBtnText;
    }

    public void setEmptyBtnText(CharSequence emptyBtnText) {
        this.mEmptyBtnText = emptyBtnText;
    }

    public void setOnEmptyClickListener(OnEmptyOrErrorClickListener onEmptyClickListener) {
        this.mOEmptyClickListener = onEmptyClickListener;
    }

    public MryTextView getTextView() {
        return this.mTextView;
    }

    public MryRoundButton getBtn() {
        return this.mBtn;
    }

    public int getCurrentStatus() {
        return this.mCurrentStatus;
    }
}
