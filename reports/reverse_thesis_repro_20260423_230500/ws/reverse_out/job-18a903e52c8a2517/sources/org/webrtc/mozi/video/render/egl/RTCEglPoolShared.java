package org.webrtc.mozi.video.render.egl;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.webrtc.mozi.EglBase;
import org.webrtc.mozi.EglBase14;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.video.render.egl.RTCEglSharedController;

/* JADX INFO: loaded from: classes3.dex */
public class RTCEglPoolShared implements RTCEglPool {
    private static final int DEFAULT_GROUP_CAPACITY = 5;
    private static final int MAX_GROUP_CAPACITY = 10;
    private static final int MIN_GROUP_CAPACITY = 1;
    private static final String TAG = "EglPoolShared";
    List<EglGroup> mEglGroups;
    int mGroupCapacity;
    boolean mOptConcurrentAccess;
    boolean mRemoveSyncLock;
    boolean mStrictConfigAttributes;

    static class EglGroup {
        int mCapacity;
        int[] mConfigAttributes;
        private final boolean mOptConcurrentAccess;
        boolean mReleased;
        RTCEglController mSharedController;
        List<RTCEglController> mSharingControllers = new LinkedList();

        EglGroup(EglBase.Context sharedContext, int[] configAttributes, int capacity, boolean optConcurrentAccess) {
            this.mSharedController = new RTCEglStandardController(sharedContext, configAttributes);
            this.mConfigAttributes = configAttributes;
            this.mCapacity = capacity;
            this.mOptConcurrentAccess = optConcurrentAccess;
        }

        RTCEglController shareController() {
            RTCEglSharedController controllerShared = new RTCEglSharedController(this.mSharedController);
            controllerShared.setReleaseCallback(new RTCEglSharedController.ReleaseCallback() { // from class: org.webrtc.mozi.video.render.egl.RTCEglPoolShared.EglGroup.1
                @Override // org.webrtc.mozi.video.render.egl.RTCEglSharedController.ReleaseCallback
                public void onRelease(RTCEglSharedController eglControllerShared) {
                    synchronized (EglGroup.this.mSharingControllers) {
                        EglGroup.this.mSharingControllers.remove(eglControllerShared);
                        if (EglGroup.this.mReleased && EglGroup.this.mSharingControllers.isEmpty()) {
                            EglGroup.this.mSharedController.release();
                        }
                    }
                }
            });
            if (this.mOptConcurrentAccess) {
                synchronized (this.mSharingControllers) {
                    this.mSharingControllers.add(controllerShared);
                }
            } else {
                this.mSharingControllers.add(controllerShared);
            }
            return controllerShared;
        }

        boolean isOverLoad() {
            boolean z;
            synchronized (this.mSharingControllers) {
                z = this.mSharingControllers.size() >= this.mCapacity;
            }
            return z;
        }

        int getSharingCount() {
            int size;
            synchronized (this.mSharingControllers) {
                size = this.mSharingControllers.size();
            }
            return size;
        }

        void release() {
            synchronized (this.mSharingControllers) {
                this.mReleased = true;
                if (this.mSharingControllers.isEmpty()) {
                    this.mSharedController.release();
                }
            }
        }
    }

    public RTCEglPoolShared(boolean strictConfigAttributes, boolean removeSyncLock, boolean optConcurrentAccess) {
        this(10, strictConfigAttributes, removeSyncLock, optConcurrentAccess);
    }

    public RTCEglPoolShared(int groupCapacity, boolean strictConfigAttributes, boolean removeSyncLock, boolean optConcurrentAccess) {
        this.mEglGroups = new LinkedList();
        if (groupCapacity > 10) {
            groupCapacity = 10;
        } else if (groupCapacity < 1) {
            groupCapacity = 1;
        }
        this.mGroupCapacity = groupCapacity;
        this.mStrictConfigAttributes = strictConfigAttributes;
        this.mRemoveSyncLock = removeSyncLock;
        this.mOptConcurrentAccess = optConcurrentAccess;
    }

    public static boolean isSupported() {
        return EglBase14.isEGL14Supported();
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglPool
    public RTCEglController create(EglBase.Context sharedContext, int[] configAttributes) {
        RTCEglController rTCEglControllerCreateInternal;
        Logging.d(TAG, "create, sharedContext:" + sharedContext);
        if (this.mRemoveSyncLock) {
            return createInternal(sharedContext, configAttributes);
        }
        synchronized (this.mEglGroups) {
            rTCEglControllerCreateInternal = createInternal(sharedContext, configAttributes);
        }
        return rTCEglControllerCreateInternal;
    }

    private RTCEglController createInternal(EglBase.Context sharedContext, int[] configAttributes) {
        EglGroup targetGroup = null;
        for (EglGroup group : this.mEglGroups) {
            if (group != null && !group.isOverLoad() && (!this.mStrictConfigAttributes || Arrays.equals(configAttributes, group.mConfigAttributes))) {
                if (targetGroup == null || group.getSharingCount() < targetGroup.getSharingCount()) {
                    targetGroup = group;
                }
            }
        }
        if (targetGroup == null) {
            targetGroup = new EglGroup(sharedContext, configAttributes, this.mGroupCapacity, this.mOptConcurrentAccess);
            this.mEglGroups.add(targetGroup);
            Logging.d(TAG, "new egl group, total size : " + this.mEglGroups.size());
        }
        return targetGroup.shareController();
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglPool
    public void release() {
        Logging.d(TAG, "release");
        if (this.mRemoveSyncLock) {
            for (EglGroup group : this.mEglGroups) {
                group.release();
            }
            this.mEglGroups.clear();
            return;
        }
        synchronized (this.mEglGroups) {
            for (EglGroup group2 : this.mEglGroups) {
                group2.release();
            }
            this.mEglGroups.clear();
        }
    }
}
