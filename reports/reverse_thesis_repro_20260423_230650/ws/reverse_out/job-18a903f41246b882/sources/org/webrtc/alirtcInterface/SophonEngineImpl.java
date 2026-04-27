package org.webrtc.alirtcInterface;

import android.content.Context;
import android.os.Looper;
import android.text.TextUtils;
import android.util.Log;
import android.view.SurfaceHolder;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.webrtc.alirtcInterface.ALI_RTC_INTERFACE;
import org.webrtc.alirtcInterface.SophonEngine;
import org.webrtc.audio.AppRTCAudioManager;
import org.webrtc.model.SophonViewStatus;
import org.webrtc.sdk.SophonSurfaceView;
import org.webrtc.utils.AlivcLog;

/* JADX INFO: loaded from: classes3.dex */
public class SophonEngineImpl extends SophonEngine {
    private static final int HIGH_DEFINITION_HEIGHT = 1280;
    private static final int HIGH_DEFINITION_WIDTH = 720;
    private static final String TAG = "SophonEngine";
    private final int TIME_OUT_SECOND;
    private AppRTCAudioManager audioManager;
    private boolean enableHighDefinitionPreview;
    private String extras;
    private Map<ALI_RTC_INTERFACE.AliRTCSdk_VideSource_Type, SophonViewStatus> localViewStatus;
    private WeakReference<Context> mContext;
    private boolean mIsBasicMusicMode;
    private final ReentrantLock mLock;
    private ALI_RTC_INTERFACE m_nAliRTCInterface;
    private Map<String, Map<ALI_RTC_INTERFACE.AliRTCSdk_VideSource_Type, SophonViewStatus>> remoteViewStatus;
    private SophonEventListener sophonEventListener;

    enum ProcessWindow {
        ADD_REMOTE,
        ADD_LOCAL,
        REMOVE_REMOTE,
        REMOVE_LOCAL,
        UPDATE
    }

    public SophonEngineImpl(Context context, String extras, SophonEventListener listener) {
        boolean z = false;
        this.mIsBasicMusicMode = false;
        this.extras = "";
        this.remoteViewStatus = new HashMap();
        this.localViewStatus = new HashMap();
        this.mLock = new ReentrantLock();
        this.TIME_OUT_SECOND = 3;
        this.enableHighDefinitionPreview = true;
        this.mContext = new WeakReference<>(context);
        this.sophonEventListener = listener;
        this.extras = extras;
        if (extras != null && (extras.contains(ALI_RTC_INTERFACE.SCENE_MEDIA_MODE) || this.extras.contains(ALI_RTC_INTERFACE.SCENE_MUSIC_MODE))) {
            z = true;
        }
        this.mIsBasicMusicMode = z;
    }

    public SophonEngineImpl(Context context, SophonEventListener listener) {
        this.mIsBasicMusicMode = false;
        this.extras = "";
        this.remoteViewStatus = new HashMap();
        this.localViewStatus = new HashMap();
        this.mLock = new ReentrantLock();
        this.TIME_OUT_SECOND = 3;
        this.enableHighDefinitionPreview = true;
        this.mContext = new WeakReference<>(context);
        this.sophonEventListener = listener;
        this.mIsBasicMusicMode = false;
    }

    public SophonEngineImpl create() {
        ALI_RTC_INTERFACE_IMPL ali_rtc_interface_impl = new ALI_RTC_INTERFACE_IMPL();
        this.m_nAliRTCInterface = ali_rtc_interface_impl;
        ali_rtc_interface_impl.SetContext(this.mContext.get());
        AliSophonEngineImpl aliSophonEnginel = new AliSophonEngineImpl(this.mContext.get(), this.m_nAliRTCInterface, this.sophonEventListener);
        AlivcLog.create(this.m_nAliRTCInterface);
        AlivcLog.d(TAG, "log init");
        AlivcLog.i(TAG, "[API]getCurrentThreadID:" + Looper.getMainLooper().getThread().getId());
        if (this.m_nAliRTCInterface.Create(this.extras, aliSophonEnginel) == 0) {
            return null;
        }
        AppRTCAudioManager appRTCAudioManagerCreate = AppRTCAudioManager.create(this.mContext.get());
        this.audioManager = appRTCAudioManagerCreate;
        appRTCAudioManagerCreate.start(new AppRTCAudioManager.AudioManagerEvents() { // from class: org.webrtc.alirtcInterface.SophonEngineImpl.1
            @Override // org.webrtc.audio.AppRTCAudioManager.AudioManagerEvents
            public void onAudioDeviceChanged(AppRTCAudioManager.AudioDevice audioDevice, Set<AppRTCAudioManager.AudioDevice> availableAudioDevices) {
                SophonEngineImpl.this.onAudioManagerDevicesChanged(audioDevice, availableAudioDevices);
            }

            @Override // org.webrtc.audio.AppRTCAudioManager.AudioManagerEvents
            public void onPhoneStateChanged(int state) {
                if (SophonEngineImpl.this.m_nAliRTCInterface != null) {
                    if (state == 0) {
                        Log.e(SophonEngineImpl.TAG, "电话挂断");
                        SophonEngineImpl.this.m_nAliRTCInterface.applicationMicInterruptResume();
                    } else if (state == 1) {
                        Log.e(SophonEngineImpl.TAG, "电话响铃");
                    } else if (state == 2) {
                        Log.e(SophonEngineImpl.TAG, "来电接通 或者 去电，去电接通  但是没法区分");
                        SophonEngineImpl.this.m_nAliRTCInterface.applicationMicInterrupt();
                    }
                }
            }
        });
        return this;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void setCollectStatusListener(CollectStatusListener collectStatusListener) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.setCollectStatusListener(collectStatusListener);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onAudioManagerDevicesChanged(AppRTCAudioManager.AudioDevice device, Set<AppRTCAudioManager.AudioDevice> availableDevices) {
        AlivcLog.i(TAG, "onAudioManagerDevicesChanged: " + availableDevices + ", selected: " + device);
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x004d  */
    @Override // org.webrtc.alirtcInterface.SophonEngine
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void destory() {
        /*
            r6 = this;
            java.lang.String r0 = "destory: mLock.tryLock time out !!"
            java.lang.String r1 = "SophonEngine"
            org.webrtc.audio.AppRTCAudioManager r2 = r6.audioManager
            if (r2 == 0) goto L10
            org.webrtc.alirtcInterface.SophonEngineImpl$2 r2 = new org.webrtc.alirtcInterface.SophonEngineImpl$2
            r2.<init>()
            org.webrtc.ali.ThreadUtils.runOnUiThread(r2)
        L10:
            destroy()
            org.webrtc.alirtcInterface.ALI_RTC_INTERFACE r2 = r6.m_nAliRTCInterface
            if (r2 == 0) goto L61
            java.util.concurrent.locks.ReentrantLock r2 = r6.mLock     // Catch: java.lang.Throwable -> L3f java.lang.InterruptedException -> L41
            r3 = 3
            java.util.concurrent.TimeUnit r5 = java.util.concurrent.TimeUnit.SECONDS     // Catch: java.lang.Throwable -> L3f java.lang.InterruptedException -> L41
            boolean r2 = r2.tryLock(r3, r5)     // Catch: java.lang.Throwable -> L3f java.lang.InterruptedException -> L41
            if (r2 == 0) goto L30
            org.webrtc.alirtcInterface.ALI_RTC_INTERFACE r0 = r6.m_nAliRTCInterface     // Catch: java.lang.Throwable -> L3f java.lang.InterruptedException -> L41
            if (r0 == 0) goto L36
            org.webrtc.alirtcInterface.ALI_RTC_INTERFACE r0 = r6.m_nAliRTCInterface     // Catch: java.lang.Throwable -> L3f java.lang.InterruptedException -> L41
            r0.Destory()     // Catch: java.lang.Throwable -> L3f java.lang.InterruptedException -> L41
            r0 = 0
            r6.m_nAliRTCInterface = r0     // Catch: java.lang.Throwable -> L3f java.lang.InterruptedException -> L41
            goto L36
        L30:
            android.util.Log.e(r1, r0)     // Catch: java.lang.Throwable -> L3f java.lang.InterruptedException -> L41
            org.webrtc.utils.AlivcLog.i(r1, r0)     // Catch: java.lang.Throwable -> L3f java.lang.InterruptedException -> L41
        L36:
            java.util.concurrent.locks.ReentrantLock r0 = r6.mLock
            boolean r0 = r0.isHeldByCurrentThread()
            if (r0 == 0) goto L61
            goto L4d
        L3f:
            r0 = move-exception
            goto L53
        L41:
            r0 = move-exception
            r0.printStackTrace()     // Catch: java.lang.Throwable -> L3f
            java.util.concurrent.locks.ReentrantLock r0 = r6.mLock
            boolean r0 = r0.isHeldByCurrentThread()
            if (r0 == 0) goto L61
        L4d:
            java.util.concurrent.locks.ReentrantLock r0 = r6.mLock
            r0.unlock()
            goto L61
        L53:
            java.util.concurrent.locks.ReentrantLock r1 = r6.mLock
            boolean r1 = r1.isHeldByCurrentThread()
            if (r1 == 0) goto L60
            java.util.concurrent.locks.ReentrantLock r1 = r6.mLock
            r1.unlock()
        L60:
            throw r0
        L61:
            org.webrtc.utils.AlivcLog.destroy()
            org.webrtc.utils.AlivcLog.release()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.webrtc.alirtcInterface.SophonEngineImpl.destory():void");
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public String getSDKVersion() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.GetSDKVersion();
        }
        return "";
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int gslb(ALI_RTC_INTERFACE.AuthInfo authInfo) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return -1;
        }
        int result = ali_rtc_interface.Gslb(authInfo);
        return result;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int joinChannel(String display_name) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return -1;
        }
        int result = ali_rtc_interface.JoinChannel(display_name);
        return result;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int joinChannel(ALI_RTC_INTERFACE.AuthInfo authInfo, String displayName) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return -1;
        }
        int result = ali_rtc_interface.JoinChannel(authInfo, displayName);
        return result;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int leaveChannel() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return -1;
        }
        int result = ali_rtc_interface.LeaveChannel();
        return result;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int leaveChannel(long timeout) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return -1;
        }
        int result = ali_rtc_interface.LeaveChannel(timeout);
        return result;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int enableHighDefinitionPreview(boolean enable) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return -1;
        }
        this.enableHighDefinitionPreview = enable;
        int ret = ali_rtc_interface.enableHighDefinitionPreview(enable);
        Log.e(TAG, "enableHighDefinitionPreview:" + ret);
        return ret;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void openCamera(ALI_RTC_INTERFACE.AliCameraConfig aliCameraConfig) {
        if (this.m_nAliRTCInterface != null) {
            if (this.enableHighDefinitionPreview) {
                aliCameraConfig.preferWidth = HIGH_DEFINITION_WIDTH;
                aliCameraConfig.preferHeight = HIGH_DEFINITION_HEIGHT;
            }
            this.m_nAliRTCInterface.OpenCamera(aliCameraConfig);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void closeCamera() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.CloseCamera();
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void addLocalDisplayWindow(final ALI_RTC_INTERFACE.AliRTCSdk_VideSource_Type videoSourceType, final SophonEngine.AliRendererConfig config) {
        AlivcLog.d(TAG, "addLocalDisplayWindowtextid = " + config.textureId);
        final SophonViewStatus viewStatus = new SophonViewStatus();
        viewStatus.surfaceView = new WeakReference<>(config.displayView);
        viewStatus.flip = config.flip;
        this.localViewStatus.put(videoSourceType, viewStatus);
        if (config.textureId > 0) {
            viewStatus.setAddDisplayWindow(true);
            processDisplayWindowInternal(null, videoSourceType, config, ProcessWindow.ADD_LOCAL);
            return;
        }
        if (config.displayView != null && ((SophonSurfaceView) config.displayView).isCreate()) {
            viewStatus.setAddDisplayWindow(true);
            processDisplayWindowInternal(null, videoSourceType, config, ProcessWindow.ADD_LOCAL);
        }
        ((SophonSurfaceView) config.displayView).setSophonViewStatus(viewStatus);
        ((SophonSurfaceView) config.displayView).setListener(new SophonSurfaceView.SophonSurfaceChange() { // from class: org.webrtc.alirtcInterface.SophonEngineImpl.3
            @Override // org.webrtc.sdk.SophonSurfaceView.SophonSurfaceChange
            public void onsurfaceCreated(SurfaceHolder holder, int width, int height, SophonViewStatus status) {
                if (status == null || status.isAddDisplayWindow) {
                    return;
                }
                config.height = height;
                config.width = width;
                config.flip = viewStatus.flip;
                status.setAddDisplayWindow(true);
                AlivcLog.d(SophonEngineImpl.TAG, "onsurfaceCreated config.filp = " + config.flip + "holder = " + holder);
                SophonEngineImpl.this.processDisplayWindowInternal(null, videoSourceType, config, ProcessWindow.ADD_LOCAL);
            }

            @Override // org.webrtc.sdk.SophonSurfaceView.SophonSurfaceChange
            public void onSurfaceChange(SurfaceHolder holder, int width, int height, SophonViewStatus status) {
                config.height = height;
                config.width = width;
                config.flip = viewStatus.flip;
                AlivcLog.d(SophonEngineImpl.TAG, "onSurfaceChange config.filp = " + config.flip + "holder = " + holder);
                SophonEngineImpl.this.processDisplayWindowInternal(null, null, config, ProcessWindow.UPDATE);
            }

            @Override // org.webrtc.sdk.SophonSurfaceView.SophonSurfaceChange
            public void onSurfaceDestroyed(SurfaceHolder holder, SophonViewStatus status) {
                if (status == null || !status.isAddDisplayWindow) {
                    return;
                }
                status.setAddDisplayWindow(false);
                AlivcLog.d(SophonEngineImpl.TAG, "onSurfaceDestroyed holder = " + holder);
                SophonEngineImpl.this.processDisplayWindowInternal(null, videoSourceType, null, ProcessWindow.REMOVE_LOCAL);
            }
        });
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void removeLocalDisplayWindow(ALI_RTC_INTERFACE.AliRTCSdk_VideSource_Type videoSourceType) {
        SophonViewStatus status = this.localViewStatus.get(videoSourceType);
        if (status != null) {
            status.setAddDisplayWindow(false);
            if (status.surfaceView != null && status.surfaceView.get() != null) {
                ((SophonSurfaceView) status.surfaceView.get()).setSophonViewStatus(null);
                ((SophonSurfaceView) status.surfaceView.get()).removeListener();
            }
            this.localViewStatus.remove(videoSourceType);
        }
        processDisplayWindowInternal(null, videoSourceType, null, ProcessWindow.REMOVE_LOCAL);
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void updateDisplayWindow(SophonEngine.AliRendererConfig aliRendererConfig) {
        if (aliRendererConfig != null && (aliRendererConfig.displayView instanceof SophonSurfaceView) && ((SophonSurfaceView) aliRendererConfig.displayView).getSophonViewStatus() != null) {
            ((SophonSurfaceView) aliRendererConfig.displayView).getSophonViewStatus().flip = aliRendererConfig.flip;
        }
        processDisplayWindowInternal(null, null, aliRendererConfig, ProcessWindow.UPDATE);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processDisplayWindowInternal(String callid, ALI_RTC_INTERFACE.AliRTCSdk_VideSource_Type videSourceType, SophonEngine.AliRendererConfig config, ProcessWindow pw) {
        try {
            if (this.m_nAliRTCInterface != null) {
                try {
                    if (!this.mLock.tryLock(3L, TimeUnit.SECONDS)) {
                        Log.e(TAG, "processDisplayWindowInternal: mLock.tryLock time out !!");
                        AlivcLog.i(TAG, "processDisplayWindowInternal: mLock.tryLock time out !!");
                    } else if (this.m_nAliRTCInterface != null) {
                        ALI_RTC_INTERFACE.AliRendererConfig aliRendererConfig = null;
                        if (config != null) {
                            aliRendererConfig = new ALI_RTC_INTERFACE.AliRendererConfig();
                            aliRendererConfig.height = config.height;
                            aliRendererConfig.width = config.width;
                            if (config.displayView != null) {
                                aliRendererConfig.display_view = config.displayView.getHolder().getSurface();
                                aliRendererConfig.render_id = config.displayView.getHolder().getSurface().hashCode();
                            }
                            aliRendererConfig.display_mode = config.displayMode;
                            aliRendererConfig.flip = config.flip;
                            aliRendererConfig.sharedContext = config.sharedContext;
                            aliRendererConfig.enableBeauty = config.enableBeauty;
                            if (config.textureId > 0) {
                                aliRendererConfig.textureId = config.textureId;
                                aliRendererConfig.textureWidth = config.textureWidth;
                                aliRendererConfig.textureHeight = config.textureHeight;
                                aliRendererConfig.render_id = config.textureId;
                            }
                            AlivcLog.d(TAG, "processDisplayWindowInternal videSourceType =  " + videSourceType + " config.filp = " + config.flip + " pw = " + pw);
                        }
                        int i = AnonymousClass5.$SwitchMap$org$webrtc$alirtcInterface$SophonEngineImpl$ProcessWindow[pw.ordinal()];
                        boolean z = true;
                        if (i != 1) {
                            if (i == 2) {
                                StringBuilder sb = new StringBuilder();
                                sb.append("processDisplayWindowInternal ADD_REMOTE =  ");
                                if (aliRendererConfig == null || TextUtils.isEmpty(callid)) {
                                    z = false;
                                }
                                sb.append(z);
                                AlivcLog.d(TAG, sb.toString());
                                if (aliRendererConfig != null && !TextUtils.isEmpty(callid)) {
                                    this.m_nAliRTCInterface.AddRemoteDisplayWindow(callid, videSourceType, aliRendererConfig);
                                }
                            } else if (i == 3) {
                                this.m_nAliRTCInterface.RemoveLocalDisplayWindow(videSourceType);
                            } else if (i != 4) {
                                if (i == 5 && aliRendererConfig != null) {
                                    this.m_nAliRTCInterface.UpdateDisplayWindow(aliRendererConfig);
                                }
                            } else if (!TextUtils.isEmpty(callid)) {
                                this.m_nAliRTCInterface.RemoveRemoteDisplayWindow(callid, videSourceType);
                            }
                        } else if (aliRendererConfig != null) {
                            this.m_nAliRTCInterface.AddLocalDisplayWindow(videSourceType, aliRendererConfig);
                        }
                    }
                    if (!this.mLock.isHeldByCurrentThread()) {
                        return;
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                    if (!this.mLock.isHeldByCurrentThread()) {
                        return;
                    }
                }
                this.mLock.unlock();
            }
        } catch (Throwable th) {
            if (this.mLock.isHeldByCurrentThread()) {
                this.mLock.unlock();
            }
            throw th;
        }
    }

    /* JADX INFO: renamed from: org.webrtc.alirtcInterface.SophonEngineImpl$5, reason: invalid class name */
    static /* synthetic */ class AnonymousClass5 {
        static final /* synthetic */ int[] $SwitchMap$org$webrtc$alirtcInterface$SophonEngineImpl$ProcessWindow;

        static {
            int[] iArr = new int[ProcessWindow.values().length];
            $SwitchMap$org$webrtc$alirtcInterface$SophonEngineImpl$ProcessWindow = iArr;
            try {
                iArr[ProcessWindow.ADD_LOCAL.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$org$webrtc$alirtcInterface$SophonEngineImpl$ProcessWindow[ProcessWindow.ADD_REMOTE.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$org$webrtc$alirtcInterface$SophonEngineImpl$ProcessWindow[ProcessWindow.REMOVE_LOCAL.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$org$webrtc$alirtcInterface$SophonEngineImpl$ProcessWindow[ProcessWindow.REMOVE_REMOTE.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$org$webrtc$alirtcInterface$SophonEngineImpl$ProcessWindow[ProcessWindow.UPDATE.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void addRemoteDisplayWindow(final String callId, final ALI_RTC_INTERFACE.AliRTCSdk_VideSource_Type videoSourceType, final SophonEngine.AliRendererConfig config) {
        Map<ALI_RTC_INTERFACE.AliRTCSdk_VideSource_Type, SophonViewStatus> viewStatusMap = this.remoteViewStatus.get(callId);
        if (viewStatusMap == null) {
            viewStatusMap = new HashMap();
            this.remoteViewStatus.put(callId, viewStatusMap);
        }
        SophonViewStatus viewStatus = new SophonViewStatus();
        viewStatus.surfaceView = new WeakReference<>(config.displayView);
        viewStatus.flip = config.flip;
        viewStatusMap.put(videoSourceType, viewStatus);
        if (config.displayView != null && ((SophonSurfaceView) config.displayView).isCreate()) {
            AlivcLog.i(TAG, "addRemoteDisplayWindow: displayView != null displayView  is isCreate ");
            viewStatus.setAddDisplayWindow(true);
            processDisplayWindowInternal(callId, videoSourceType, config, ProcessWindow.ADD_REMOTE);
        } else if (config.textureId > 0) {
            AlivcLog.i(TAG, "addRemoteDisplayWindow: videoCanvas.textureId != 0 videoCanvas.textureId is = " + config.textureId);
            viewStatus.setAddDisplayWindow(true);
            processDisplayWindowInternal(callId, videoSourceType, config, ProcessWindow.ADD_REMOTE);
            return;
        }
        ((SophonSurfaceView) config.displayView).setSophonViewStatus(viewStatus);
        ((SophonSurfaceView) config.displayView).setListener(new SophonSurfaceView.SophonSurfaceChange() { // from class: org.webrtc.alirtcInterface.SophonEngineImpl.4
            @Override // org.webrtc.sdk.SophonSurfaceView.SophonSurfaceChange
            public void onsurfaceCreated(SurfaceHolder holder, int width, int height, SophonViewStatus status) {
                if (status == null || status.isAddDisplayWindow) {
                    return;
                }
                config.height = height;
                config.width = width;
                config.flip = status.flip;
                status.setAddDisplayWindow(true);
                AlivcLog.d(SophonEngineImpl.TAG, "onsurfaceCreated config.filp = " + config.flip + "holder = " + holder);
                SophonEngineImpl.this.processDisplayWindowInternal(callId, videoSourceType, config, ProcessWindow.ADD_REMOTE);
            }

            @Override // org.webrtc.sdk.SophonSurfaceView.SophonSurfaceChange
            public void onSurfaceChange(SurfaceHolder holder, int width, int height, SophonViewStatus status) {
                config.height = height;
                config.width = width;
                config.flip = status.flip;
                AlivcLog.d(SophonEngineImpl.TAG, "onSurfaceChange config.filp = " + config.flip + "holder = " + holder);
                SophonEngineImpl.this.processDisplayWindowInternal(null, null, config, ProcessWindow.UPDATE);
            }

            @Override // org.webrtc.sdk.SophonSurfaceView.SophonSurfaceChange
            public void onSurfaceDestroyed(SurfaceHolder holder, SophonViewStatus status) {
                if (status == null || !status.isAddDisplayWindow) {
                    return;
                }
                status.setAddDisplayWindow(false);
                AlivcLog.d(SophonEngineImpl.TAG, "onSurfaceDestroyed holder = " + holder);
                SophonEngineImpl.this.processDisplayWindowInternal(callId, videoSourceType, null, ProcessWindow.REMOVE_REMOTE);
            }
        });
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void removeRemoteDisplayWindow(String callId, ALI_RTC_INTERFACE.AliRTCSdk_VideSource_Type videoSourceType) {
        Map<ALI_RTC_INTERFACE.AliRTCSdk_VideSource_Type, SophonViewStatus> viewStatusMap = this.remoteViewStatus.get(callId);
        if (viewStatusMap != null) {
            SophonViewStatus status = viewStatusMap.get(videoSourceType);
            if (status != null) {
                status.setAddDisplayWindow(false);
                if (status.surfaceView != null && status.surfaceView.get() != null) {
                    ((SophonSurfaceView) status.surfaceView.get()).setSophonViewStatus(null);
                    ((SophonSurfaceView) status.surfaceView.get()).removeListener();
                }
                viewStatusMap.remove(videoSourceType);
            }
            if (viewStatusMap.isEmpty()) {
                this.remoteViewStatus.remove(callId);
            }
        }
        processDisplayWindowInternal(callId, videoSourceType, null, ProcessWindow.REMOVE_REMOTE);
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void publish(ALI_RTC_INTERFACE.AliPublishConfig publishConfig) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.Publish(publishConfig);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void republish(ALI_RTC_INTERFACE.AliPublishConfig publishConfig) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.Republish(publishConfig);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void unpublish() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.Unpublish();
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void subscribe(String callId, ALI_RTC_INTERFACE.AliSubscribeConfig subscribeConfig) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.Subscribe(callId, subscribeConfig);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void resubscribe(String callId, ALI_RTC_INTERFACE.AliSubscribeConfig subscribeConfig) {
        AlivcLog.d(TAG, "stream_label " + subscribeConfig.stream_label + " audio_track_label " + subscribeConfig.audio_track_label);
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.Resubscribe(callId, subscribeConfig);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void unsubscribe(String callId) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.Unsubscribe(callId);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public ALI_RTC_INTERFACE.AliCaptureType getCaptureType() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return null;
        }
        ALI_RTC_INTERFACE.AliCaptureType type = ali_rtc_interface.GetCaptureType();
        return type;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int switchCramer() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return -1;
        }
        int ret = ali_rtc_interface.SwitchCramer();
        return ret;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int setFlash(boolean flash) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return -1;
        }
        int ret = ali_rtc_interface.SetFlash(flash);
        return ret;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int setCameraZoom(float zoom) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return -1;
        }
        int ret = ali_rtc_interface.SetCameraZoom(zoom);
        return ret;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public boolean isCameraSupportFocusPoint() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return false;
        }
        boolean ret = ali_rtc_interface.isCameraSupportFocusPoint();
        return ret;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public boolean isCameraSupportExposurePoint() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return false;
        }
        boolean ret = ali_rtc_interface.isCameraSupportExposurePoint();
        return ret;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int setCameraFocusPoint(float x, float y) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return -1;
        }
        int ret = ali_rtc_interface.setCameraFocusPoint(x, y);
        return ret;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int setCameraExposurePoint(float x, float y) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return -1;
        }
        int ret = ali_rtc_interface.setCameraExposurePoint(x, y);
        return ret;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int setRecordingVolume(int volume) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return 0;
        }
        int ret = ali_rtc_interface.setRecordingVolume(volume);
        return ret;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int setPlayoutVolume(int volume) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return 0;
        }
        int ret = ali_rtc_interface.setPlayoutVolume(volume);
        return ret;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void enableLocalVideo(ALI_RTC_INTERFACE.AliRTCSdk_VideSource_Type videSourceType, boolean enable) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.EnableLocalVideo(videSourceType, enable);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void enableLocalAudio(boolean enable) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.EnableLocalAudio(enable);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void setSpeakerStatus(boolean enable) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.SetSpeakerStatus(enable);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void enableRemoteVideo(String callId, ALI_RTC_INTERFACE.AliRTCSdk_VideSource_Type videSourceType, boolean enable) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.EnableRemoteVideo(callId, videSourceType, enable);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void enableRemoteAudio(String callId, boolean enable) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.EnableRemoteAudio(callId, enable);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void selectSpeakePhone(boolean bool) {
        StringBuilder sb = new StringBuilder();
        sb.append("selectSpeakePhone:");
        sb.append(bool);
        sb.append("audioManager is null");
        sb.append(this.audioManager == null);
        AlivcLog.d(TAG, sb.toString());
        AppRTCAudioManager appRTCAudioManager = this.audioManager;
        if (appRTCAudioManager != null) {
            appRTCAudioManager.setBasicMusicMode(this.mIsBasicMusicMode);
            this.audioManager.setBasicMusicModeVolume();
            this.audioManager.setDefaultAudioDevice(bool ? AppRTCAudioManager.AudioDevice.SPEAKER_PHONE : AppRTCAudioManager.AudioDevice.EARPIECE);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void pauseRender() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.PauseRender();
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void resumeRender() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.ResumeRender();
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public ALI_RTC_INTERFACE.TransportStatus getTransportStatus(String callId, ALI_RTC_INTERFACE.TransportType type) {
        ALI_RTC_INTERFACE.TransportStatus result = ALI_RTC_INTERFACE.TransportStatus.Network_Unknow;
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.GetTransportStatus(callId, type);
        }
        return result;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public String[] enumerateAllCaptureDevices() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return null;
        }
        return ali_rtc_interface.EnumerateAllCaptureDevices();
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int setCaptureDeviceByName(String deviceName) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return -1;
        }
        int result = ali_rtc_interface.SetCaptureDeviceByName(deviceName);
        return result;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void changeLogLevel(ALI_RTC_INTERFACE.AliRTCSDKLogLevel level) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.ChangeLogLevel(level);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void uploadLop() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.UploadLog();
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int respondMessageNotification(String tid, String contentType, String content) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return -1;
        }
        int result = ali_rtc_interface.RespondMessageNotification(tid, contentType, content);
        return result;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int uplinkChannelMessage(String contentType, String content) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return -1;
        }
        int result = ali_rtc_interface.UplinkChannelMessage(contentType, content);
        return result;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void RegisterAudioObserver(ALI_RTC_INTERFACE.AliAudioType type, ALI_RTC_INTERFACE.AliAudioObserver observer) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.RegisterAudioObserver(type, observer);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void UnRegisterAudioObserver(ALI_RTC_INTERFACE.AliAudioType type) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.UnRegisterAudioObserver(type);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void RegisterYUVObserver(String callId, ALI_RTC_INTERFACE.AliVideoObserver observer) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.RegisterYUVObserver(callId, observer);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void UnRegisterYUVObserver(String callId) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.UnRegisterYUVObserver(callId);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void RegisterVideoObserver(ALI_RTC_INTERFACE.AliVideoObserver observer) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.RegisterVideoObserver(observer);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void UnRegisterVideoObserver() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.UnRegisterVideoObserver();
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void RegisterPreprocessVideoObserver(ALI_RTC_INTERFACE.AliDetectObserver observer) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.RegisterPreprocessVideoObserver(observer);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void UnRegisterPreprocessVideoObserver() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.UnRegisterPreprocessVideoObserver();
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void RegisterTexturePreObserver(String callId, ALI_RTC_INTERFACE.AliTextureObserver observer) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.RegisterTexturePreObserver(callId, observer);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void UnRegisterTexturePreObserver(String callId) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.UnRegisterTexturePreObserver(callId);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void RegisterTexturePostObserver(String callId, ALI_RTC_INTERFACE.AliTextureObserver observer) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.RegisterTexturePostObserver(callId, observer);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void UnRegisterTexturePostObserver(String callId) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.UnRegisterTexturePostObserver(callId);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void RegisterRGBAObserver(String callId, ALI_RTC_INTERFACE.AliRenderDataObserver observer) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.RegisterRGBAObserver(callId, observer);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void UnRegisterRGBAObserver(String callId) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.UnRegisterRGBAObserver(callId);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void enableBackgroundAudioRecording(boolean enable) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.enableBackgroundAudioRecording(enable);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public boolean isEnableBackgroundAudioRecording() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.isEnableBackgroundAudioRecording();
        }
        return false;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public ALI_RTC_INTERFACE.VideoRawDataInterface registerVideoRawDataInterface(ALI_RTC_INTERFACE.AliRawDataStreamType streamType) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.registerVideoRawDataInterface(streamType);
        }
        return null;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void unRegisterVideoRawDataInterface(ALI_RTC_INTERFACE.AliRawDataStreamType streamType) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.unRegisterVideoRawDataInterface(streamType);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void setTraceId(String traceId) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.setTraceId(traceId);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public String getMediaInfo(String callId, String trackId, String[] keys) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface == null) {
            return null;
        }
        String result = ali_rtc_interface.getMediaInfo(callId, trackId, keys);
        return result;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int startAudioCapture() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.startAudioCapture();
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int stopAudioCapture() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.stopAudioCapture();
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int startAudioPlayer() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.startAudioPlayer();
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int stopAudioPlayer() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.stopAudioPlayer();
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public AppRTCAudioManager.AudioDevice getSelectAudioDevice() {
        return this.audioManager.getSelectedAudioDevice();
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void setDeviceOrientationMode(ALI_RTC_INTERFACE.Ali_RTC_Device_Orientation_Mode mode) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.setDeviceOrientationMode(mode);
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int startAudioAccompany(String fileName, boolean localPlay, boolean replaceMic, int loopCycles) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.StartAudioAccompany(fileName, localPlay, replaceMic, loopCycles);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int stopAudioAccompany() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.StopAudioAccompany();
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int setAudioAccompanyVolume(int volume) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.SetAudioAccompanyVolume(volume);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int getAudioAccompanyVolume() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.GetAudioAccompanyVolume();
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int SetAudioAccompanyPublishVolume(int volume) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.SetAudioAccompanyPublishVolume(volume);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int GetAudioAccompanyPublishVolume() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.GetAudioAccompanyPublishVolume();
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int SetAudioAccompanyPlayoutVolume(int volume) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.SetAudioAccompanyPlayoutVolume(volume);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int GetAudioAccompanyPlayoutVolume() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.GetAudioAccompanyPlayoutVolume();
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int PauseAudioMixing() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.PauseAudioMixing();
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int ResumeAudioMixing() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.ResumeAudioMixing();
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int PreloadAudioEffect(int sound_id, String file_path) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.PreloadAudioEffect(sound_id, file_path);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int UnloadAudioEffect(int sound_id) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.UnloadAudioEffect(sound_id);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int PlayAudioEffect(int sound_id, String file_path, int cycles, boolean publish) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.PlayAudioEffect(sound_id, file_path, cycles, publish);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int StopAudioEffect(int sound_id) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.StopAudioEffect(sound_id);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int SetAudioEffectPublishVolume(int sound_id, int volume) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.SetAudioEffectPublishVolume(sound_id, volume);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int GetAudioEffectPublishVolume(int sound_id) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.GetAudioEffectPublishVolume(sound_id);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int SetAudioEffectPlayoutVolume(int sound_id, int volume) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.SetAudioEffectPlayoutVolume(sound_id, volume);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int GetAudioEffectPlayoutVolume(int sound_id) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.GetAudioEffectPlayoutVolume(sound_id);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int PauseAudioEffect(int sound_id) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.PauseAudioEffect(sound_id);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int ResumeAudioEffect(int sound_id) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.ResumeAudioEffect(sound_id);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int EnableEarBack(boolean enable) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.EnableEarBack(enable);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int SetEarBackVolume(int volume) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.SetEarBackVolume(volume);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int SetChannelProfile(ALI_RTC_INTERFACE.AliRTCSDK_Channel_Profile profile) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.SetChannelProfile(profile);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int SetClientRole(ALI_RTC_INTERFACE.AliRTCSDK_Client_Role role) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.SetClientRole(role);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int StartAudioFileRecording(String file_Name, int sample_Rate, int quality) {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.StartAudioFileRecording(file_Name, sample_Rate, quality);
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int StopAudioFileRecording() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            return ali_rtc_interface.StopAudioFileRecording();
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public int generateTexture() {
        int ret = this.m_nAliRTCInterface.generateTexture();
        Log.i(TAG, "generateTexture = " + ret);
        if (this.m_nAliRTCInterface != null) {
            return ret;
        }
        return -1;
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void applicationWillBecomeActive() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.applicationWillBecomeActive();
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void applicationWillResignActive() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.applicationWillResignActive();
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void applicationMicInterrupt() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.applicationMicInterrupt();
        }
    }

    @Override // org.webrtc.alirtcInterface.SophonEngine
    public void applicationMicInterruptResume() {
        ALI_RTC_INTERFACE ali_rtc_interface = this.m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.applicationMicInterruptResume();
        }
    }
}
