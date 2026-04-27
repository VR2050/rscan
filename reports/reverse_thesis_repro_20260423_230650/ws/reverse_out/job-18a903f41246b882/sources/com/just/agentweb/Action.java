package com.just.agentweb;

import android.content.Intent;
import android.net.Uri;
import com.just.agentweb.AgentActionFragment;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public final class Action {
    public static final transient int ACTION_CAMERA = 3;
    public static final transient int ACTION_FILE = 2;
    public static final transient int ACTION_PERMISSION = 1;
    public static final transient int ACTION_VIDEO = 4;
    private int mAction;
    private AgentActionFragment.ChooserListener mChooserListener;
    private int mFromIntention;
    private Intent mIntent;
    private AgentActionFragment.PermissionListener mPermissionListener;
    private ArrayList<String> mPermissions = new ArrayList<>();
    private AgentActionFragment.RationaleListener mRationaleListener;
    private Uri mUri;

    public ArrayList<String> getPermissions() {
        return this.mPermissions;
    }

    public void setPermissions(ArrayList<String> permissions) {
        this.mPermissions = permissions;
    }

    public void setPermissions(String[] permissions) {
        this.mPermissions = new ArrayList<>(Arrays.asList(permissions));
    }

    public int getAction() {
        return this.mAction;
    }

    public void setAction(int action) {
        this.mAction = action;
    }

    public int getFromIntention() {
        return this.mFromIntention;
    }

    public static Action createPermissionsAction(String[] permissions) {
        Action mAction = new Action();
        mAction.setAction(1);
        List<String> mList = Arrays.asList(permissions);
        mAction.setPermissions(new ArrayList<>(mList));
        return mAction;
    }

    public Action setFromIntention(int fromIntention) {
        this.mFromIntention = fromIntention;
        return this;
    }

    public AgentActionFragment.RationaleListener getRationaleListener() {
        return this.mRationaleListener;
    }

    public void setRationaleListener(AgentActionFragment.RationaleListener rationaleListener) {
        this.mRationaleListener = rationaleListener;
    }

    public AgentActionFragment.PermissionListener getPermissionListener() {
        return this.mPermissionListener;
    }

    public void setPermissionListener(AgentActionFragment.PermissionListener permissionListener) {
        this.mPermissionListener = permissionListener;
    }

    public AgentActionFragment.ChooserListener getChooserListener() {
        return this.mChooserListener;
    }

    public void setChooserListener(AgentActionFragment.ChooserListener chooserListener) {
        this.mChooserListener = chooserListener;
    }

    public Intent getIntent() {
        return this.mIntent;
    }

    public Uri getUri() {
        return this.mUri;
    }

    public void setUri(Uri uri) {
        this.mUri = uri;
    }

    public void setIntent(Intent intent) {
        this.mIntent = intent;
    }
}
