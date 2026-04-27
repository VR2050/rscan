package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.graphics.Typeface;
import android.hardware.Camera;
import android.os.Handler;
import android.os.HandlerThread;
import android.text.TextUtils;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MrzRecognizer;
import im.uwrkaxlmjj.messenger.camera.CameraView;
import im.uwrkaxlmjj.messenger.camera.Size;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.components.CubicBezierInterpolator;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class MrzCameraActivity extends BaseFragment implements Camera.PreviewCallback {
    private HandlerThread backgroundHandlerThread = new HandlerThread("MrzCamera");
    private CameraView cameraView;
    private MrzCameraActivityDelegate delegate;
    private TextView descriptionText;
    private Handler handler;
    private boolean recognized;
    private TextView recognizedMrzView;
    private TextView titleTextView;

    public interface MrzCameraActivityDelegate {
        void didFindMrzInfo(MrzRecognizer.Result result);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        destroy(false, null);
        getParentActivity().setRequestedOrientation(-1);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        getParentActivity().setRequestedOrientation(1);
        this.actionBar.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setItemsColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2), false);
        this.actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_actionBarWhiteSelector), false);
        this.actionBar.setCastShadows(false);
        if (!AndroidUtilities.isTablet()) {
            this.actionBar.showActionModeTop();
        }
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.MrzCameraActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    MrzCameraActivity.this.finishFragment();
                }
            }
        });
        this.fragmentView = new ViewGroup(context) { // from class: im.uwrkaxlmjj.ui.MrzCameraActivity.2
            @Override // android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int width = View.MeasureSpec.getSize(widthMeasureSpec);
                int height = View.MeasureSpec.getSize(heightMeasureSpec);
                MrzCameraActivity.this.cameraView.measure(View.MeasureSpec.makeMeasureSpec(width, 1073741824), View.MeasureSpec.makeMeasureSpec((int) (width * 0.704f), 1073741824));
                MrzCameraActivity.this.titleTextView.measure(View.MeasureSpec.makeMeasureSpec(width, 1073741824), View.MeasureSpec.makeMeasureSpec(height, 0));
                MrzCameraActivity.this.descriptionText.measure(View.MeasureSpec.makeMeasureSpec((int) (width * 0.9f), 1073741824), View.MeasureSpec.makeMeasureSpec(height, 0));
                setMeasuredDimension(width, height);
            }

            @Override // android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int l, int t, int r, int b) {
                int width = r - l;
                int height = b - t;
                MrzCameraActivity.this.cameraView.layout(0, 0, MrzCameraActivity.this.cameraView.getMeasuredWidth(), MrzCameraActivity.this.cameraView.getMeasuredHeight() + 0);
                MrzCameraActivity.this.recognizedMrzView.setTextSize(0, MrzCameraActivity.this.cameraView.getMeasuredHeight() / 22);
                MrzCameraActivity.this.recognizedMrzView.setPadding(0, 0, 0, MrzCameraActivity.this.cameraView.getMeasuredHeight() / 15);
                int y = (int) (height * 0.65f);
                MrzCameraActivity.this.titleTextView.layout(0, y, MrzCameraActivity.this.titleTextView.getMeasuredWidth(), MrzCameraActivity.this.titleTextView.getMeasuredHeight() + y);
                int y2 = (int) (height * 0.74f);
                int x = (int) (width * 0.05f);
                MrzCameraActivity.this.descriptionText.layout(x, y2, MrzCameraActivity.this.descriptionText.getMeasuredWidth() + x, MrzCameraActivity.this.descriptionText.getMeasuredHeight() + y2);
            }
        };
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        ViewGroup viewGroup = (ViewGroup) this.fragmentView;
        viewGroup.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.MrzCameraActivity.3
            @Override // android.view.View.OnTouchListener
            public boolean onTouch(View v, MotionEvent event) {
                return true;
            }
        });
        CameraView cameraView = new CameraView(context, false);
        this.cameraView = cameraView;
        cameraView.setDelegate(new CameraView.CameraViewDelegate() { // from class: im.uwrkaxlmjj.ui.MrzCameraActivity.4
            @Override // im.uwrkaxlmjj.messenger.camera.CameraView.CameraViewDelegate
            public void onCameraCreated(Camera camera) {
                Camera.Parameters params = camera.getParameters();
                float evStep = params.getExposureCompensationStep();
                float maxEv = params.getMaxExposureCompensation() * evStep;
                params.setExposureCompensation(maxEv <= 2.0f ? params.getMaxExposureCompensation() : Math.round(2.0f / evStep));
                camera.setParameters(params);
            }

            @Override // im.uwrkaxlmjj.messenger.camera.CameraView.CameraViewDelegate
            public void onCameraInit() {
                MrzCameraActivity.this.startRecognizing();
            }
        });
        viewGroup.addView(this.cameraView, LayoutHelper.createFrame(-1, -1.0f));
        TextView textView = new TextView(context);
        this.titleTextView = textView;
        textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.titleTextView.setGravity(1);
        this.titleTextView.setTextSize(1, 24.0f);
        this.titleTextView.setText(LocaleController.getString("PassportScanPassport", R.string.PassportScanPassport));
        viewGroup.addView(this.titleTextView);
        TextView textView2 = new TextView(context);
        this.descriptionText = textView2;
        textView2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
        this.descriptionText.setGravity(1);
        this.descriptionText.setTextSize(1, 16.0f);
        this.descriptionText.setText(LocaleController.getString("PassportScanPassportInfo", R.string.PassportScanPassportInfo));
        viewGroup.addView(this.descriptionText);
        TextView textView3 = new TextView(context);
        this.recognizedMrzView = textView3;
        textView3.setTypeface(Typeface.MONOSPACE);
        this.recognizedMrzView.setTextColor(-1);
        this.recognizedMrzView.setGravity(81);
        this.recognizedMrzView.setBackgroundColor(Integer.MIN_VALUE);
        this.recognizedMrzView.setAlpha(0.0f);
        this.cameraView.addView(this.recognizedMrzView);
        this.fragmentView.setKeepScreenOn(true);
        return this.fragmentView;
    }

    public void setDelegate(MrzCameraActivityDelegate mrzCameraActivityDelegate) {
        this.delegate = mrzCameraActivityDelegate;
    }

    public void destroy(boolean async, Runnable beforeDestroyRunnable) {
        this.cameraView.destroy(async, beforeDestroyRunnable);
        this.cameraView = null;
        this.backgroundHandlerThread.quitSafely();
    }

    public void hideCamera(boolean async) {
        destroy(async, null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startRecognizing() {
        this.backgroundHandlerThread.start();
        this.handler = new Handler(this.backgroundHandlerThread.getLooper());
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.MrzCameraActivity.5
            @Override // java.lang.Runnable
            public void run() {
                if (MrzCameraActivity.this.cameraView != null && !MrzCameraActivity.this.recognized && MrzCameraActivity.this.cameraView.getCameraSession() != null) {
                    MrzCameraActivity.this.cameraView.getCameraSession().setOneShotPreviewCallback(MrzCameraActivity.this);
                    AndroidUtilities.runOnUIThread(this, 500L);
                }
            }
        });
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.MrzCameraActivity$6, reason: invalid class name */
    class AnonymousClass6 implements Runnable {
        final /* synthetic */ Camera val$camera;
        final /* synthetic */ byte[] val$data;

        AnonymousClass6(byte[] bArr, Camera camera) {
            this.val$data = bArr;
            this.val$camera = camera;
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                Size size = MrzCameraActivity.this.cameraView.getPreviewSize();
                final MrzRecognizer.Result res = MrzRecognizer.recognize(this.val$data, size.getWidth(), size.getHeight(), MrzCameraActivity.this.cameraView.getCameraSession().getDisplayOrientation());
                if (res == null || TextUtils.isEmpty(res.firstName) || TextUtils.isEmpty(res.lastName) || TextUtils.isEmpty(res.number) || res.birthDay == 0) {
                    return;
                }
                if ((res.expiryDay != 0 || res.doesNotExpire) && res.gender != 0) {
                    MrzCameraActivity.this.recognized = true;
                    this.val$camera.stopPreview();
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.MrzCameraActivity.6.1
                        @Override // java.lang.Runnable
                        public void run() {
                            MrzCameraActivity.this.recognizedMrzView.setText(res.rawMRZ);
                            MrzCameraActivity.this.recognizedMrzView.animate().setDuration(200L).alpha(1.0f).setInterpolator(CubicBezierInterpolator.DEFAULT).start();
                            if (MrzCameraActivity.this.delegate != null) {
                                MrzCameraActivity.this.delegate.didFindMrzInfo(res);
                            }
                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.MrzCameraActivity.6.1.1
                                @Override // java.lang.Runnable
                                public void run() {
                                    MrzCameraActivity.this.finishFragment();
                                }
                            }, 1200L);
                        }
                    });
                }
            } catch (Exception e) {
            }
        }
    }

    @Override // android.hardware.Camera.PreviewCallback
    public void onPreviewFrame(byte[] data, Camera camera) {
        this.handler.post(new AnonymousClass6(data, camera));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarWhiteSelector), new ThemeDescription(this.titleTextView, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.descriptionText, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6)};
    }
}
