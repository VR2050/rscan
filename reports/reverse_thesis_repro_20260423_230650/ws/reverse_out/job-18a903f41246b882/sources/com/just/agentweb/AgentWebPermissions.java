package com.just.agentweb;

import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;

/* JADX INFO: loaded from: classes3.dex */
public class AgentWebPermissions {
    public static final String ACTION_CAMERA = "Camera";
    public static final String ACTION_LOCATION = "Location";
    public static final String ACTION_STORAGE = "Storage";
    public static final String[] CAMERA = {"android.permission.CAMERA"};
    public static final String[] LOCATION = {"android.permission.ACCESS_FINE_LOCATION", PermissionUtils.PERMISSION_ACCESS_COARSE_LOCATION};
    public static final String[] STORAGE = {PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE, "android.permission.WRITE_EXTERNAL_STORAGE"};
}
