package im.uwrkaxlmjj.ui.hui.discovery;

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.location.LocationManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.LocationController;
import im.uwrkaxlmjj.phoneformat.PhoneFormat;
import im.uwrkaxlmjj.ui.ChangePhoneNumberActivity;
import im.uwrkaxlmjj.ui.ChannelCreateActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.components.CombinedDrawable;
import im.uwrkaxlmjj.ui.components.ShareLocationDrawable;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import mpEIGo.juqQQs.esbSDO.R;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
public class ActionIntroActivity extends BaseFragment implements LocationController.LocationFetchCallback {
    public static final int ACTION_TYPE_CHANGE_PHONE_NUMBER = 3;
    public static final int ACTION_TYPE_CHANNEL_CREATE = 0;
    public static final int ACTION_TYPE_NEARBY_GROUP_CREATE = 2;
    public static final int ACTION_TYPE_NEARBY_LOCATION_ACCESS = 1;
    public static final int ACTION_TYPE_NEARBY_LOCATION_ENABLED = 4;
    private TextView buttonTextView;
    private String currentGroupCreateAddress;
    private String currentGroupCreateDisplayAddress;
    private int currentType;
    private TextView descriptionText;
    private TextView descriptionText2;
    private Drawable drawable1;
    private Drawable drawable2;
    private ImageView imageView;
    private TextView subtitleTextView;
    private TextView titleTextView;

    public ActionIntroActivity(int type) {
        this.currentType = type;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setItemsColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2), false);
        this.actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_actionBarWhiteSelector), false);
        this.actionBar.setCastShadows(false);
        this.actionBar.setAddToContainer(false);
        if (!AndroidUtilities.isTablet()) {
            this.actionBar.showActionModeTop();
        }
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.discovery.ActionIntroActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    ActionIntroActivity.this.finishFragment();
                }
            }
        });
        this.fragmentView = new ViewGroup(context) { // from class: im.uwrkaxlmjj.ui.hui.discovery.ActionIntroActivity.2
            /* JADX WARN: Removed duplicated region for block: B:19:0x020c  */
            @Override // android.view.View
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            protected void onMeasure(int r13, int r14) {
                /*
                    Method dump skipped, instruction units count: 886
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hui.discovery.ActionIntroActivity.AnonymousClass2.onMeasure(int, int):void");
            }

            @Override // android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int l, int t, int r, int b) {
                ActionIntroActivity.this.actionBar.layout(0, 0, r, ActionIntroActivity.this.actionBar.getMeasuredHeight());
                int width = r - l;
                int height = b - t;
                int i = ActionIntroActivity.this.currentType;
                if (i == 0) {
                    if (r > b) {
                        int y = (height - ActionIntroActivity.this.imageView.getMeasuredHeight()) / 2;
                        ActionIntroActivity.this.imageView.layout(0, y, ActionIntroActivity.this.imageView.getMeasuredWidth(), ActionIntroActivity.this.imageView.getMeasuredHeight() + y);
                        int x = (int) (width * 0.4f);
                        int y2 = (int) (height * 0.22f);
                        ActionIntroActivity.this.titleTextView.layout(x, y2, ActionIntroActivity.this.titleTextView.getMeasuredWidth() + x, ActionIntroActivity.this.titleTextView.getMeasuredHeight() + y2);
                        int x2 = (int) (width * 0.4f);
                        int y3 = (int) (height * 0.39f);
                        ActionIntroActivity.this.descriptionText.layout(x2, y3, ActionIntroActivity.this.descriptionText.getMeasuredWidth() + x2, ActionIntroActivity.this.descriptionText.getMeasuredHeight() + y3);
                        int x3 = (int) ((width * 0.4f) + (((width * 0.6f) - ActionIntroActivity.this.buttonTextView.getMeasuredWidth()) / 2.0f));
                        int y4 = (int) (height * 0.69f);
                        ActionIntroActivity.this.buttonTextView.layout(x3, y4, ActionIntroActivity.this.buttonTextView.getMeasuredWidth() + x3, ActionIntroActivity.this.buttonTextView.getMeasuredHeight() + y4);
                        return;
                    }
                    int y5 = (int) (height * 0.188f);
                    ActionIntroActivity.this.imageView.layout(0, y5, ActionIntroActivity.this.imageView.getMeasuredWidth(), ActionIntroActivity.this.imageView.getMeasuredHeight() + y5);
                    int y6 = (int) (height * 0.651f);
                    ActionIntroActivity.this.titleTextView.layout(0, y6, ActionIntroActivity.this.titleTextView.getMeasuredWidth(), ActionIntroActivity.this.titleTextView.getMeasuredHeight() + y6);
                    int y7 = (int) (height * 0.731f);
                    ActionIntroActivity.this.descriptionText.layout(0, y7, ActionIntroActivity.this.descriptionText.getMeasuredWidth(), ActionIntroActivity.this.descriptionText.getMeasuredHeight() + y7);
                    int x4 = (width - ActionIntroActivity.this.buttonTextView.getMeasuredWidth()) / 2;
                    int y8 = (int) (height * 0.853f);
                    ActionIntroActivity.this.buttonTextView.layout(x4, y8, ActionIntroActivity.this.buttonTextView.getMeasuredWidth() + x4, ActionIntroActivity.this.buttonTextView.getMeasuredHeight() + y8);
                    return;
                }
                if (i != 1) {
                    if (i == 2) {
                        if (r > b) {
                            int y9 = ((int) ((height * 0.9f) - ActionIntroActivity.this.imageView.getMeasuredHeight())) / 2;
                            ActionIntroActivity.this.imageView.layout(0, y9, ActionIntroActivity.this.imageView.getMeasuredWidth(), ActionIntroActivity.this.imageView.getMeasuredHeight() + y9);
                            int y10 = y9 + ActionIntroActivity.this.imageView.getMeasuredHeight() + AndroidUtilities.dp(10.0f);
                            ActionIntroActivity.this.subtitleTextView.layout(0, y10, ActionIntroActivity.this.subtitleTextView.getMeasuredWidth(), ActionIntroActivity.this.subtitleTextView.getMeasuredHeight() + y10);
                            int x5 = (int) (width * 0.4f);
                            int y11 = (int) (height * 0.12f);
                            ActionIntroActivity.this.titleTextView.layout(x5, y11, ActionIntroActivity.this.titleTextView.getMeasuredWidth() + x5, ActionIntroActivity.this.titleTextView.getMeasuredHeight() + y11);
                            int x6 = (int) (width * 0.4f);
                            int y12 = (int) (height * 0.26f);
                            ActionIntroActivity.this.descriptionText.layout(x6, y12, ActionIntroActivity.this.descriptionText.getMeasuredWidth() + x6, ActionIntroActivity.this.descriptionText.getMeasuredHeight() + y12);
                            int x7 = (int) ((width * 0.4f) + (((width * 0.6f) - ActionIntroActivity.this.buttonTextView.getMeasuredWidth()) / 2.0f));
                            int y13 = (int) (height * 0.6f);
                            ActionIntroActivity.this.buttonTextView.layout(x7, y13, ActionIntroActivity.this.buttonTextView.getMeasuredWidth() + x7, ActionIntroActivity.this.buttonTextView.getMeasuredHeight() + y13);
                            int x8 = (int) (width * 0.4f);
                            int y14 = (getMeasuredHeight() - ActionIntroActivity.this.descriptionText2.getMeasuredHeight()) - AndroidUtilities.dp(20.0f);
                            ActionIntroActivity.this.descriptionText2.layout(x8, y14, ActionIntroActivity.this.descriptionText2.getMeasuredWidth() + x8, ActionIntroActivity.this.descriptionText2.getMeasuredHeight() + y14);
                            return;
                        }
                        int y15 = (int) (height * 0.197f);
                        ActionIntroActivity.this.imageView.layout(0, y15, ActionIntroActivity.this.imageView.getMeasuredWidth(), ActionIntroActivity.this.imageView.getMeasuredHeight() + y15);
                        int y16 = (int) (height * 0.421f);
                        ActionIntroActivity.this.titleTextView.layout(0, y16, ActionIntroActivity.this.titleTextView.getMeasuredWidth(), ActionIntroActivity.this.titleTextView.getMeasuredHeight() + y16);
                        int y17 = (int) (height * 0.477f);
                        ActionIntroActivity.this.subtitleTextView.layout(0, y17, ActionIntroActivity.this.subtitleTextView.getMeasuredWidth(), ActionIntroActivity.this.subtitleTextView.getMeasuredHeight() + y17);
                        int y18 = (int) (height * 0.537f);
                        ActionIntroActivity.this.descriptionText.layout(0, y18, ActionIntroActivity.this.descriptionText.getMeasuredWidth(), ActionIntroActivity.this.descriptionText.getMeasuredHeight() + y18);
                        int x9 = (width - ActionIntroActivity.this.buttonTextView.getMeasuredWidth()) / 2;
                        int y19 = (int) (height * 0.71f);
                        ActionIntroActivity.this.buttonTextView.layout(x9, y19, ActionIntroActivity.this.buttonTextView.getMeasuredWidth() + x9, ActionIntroActivity.this.buttonTextView.getMeasuredHeight() + y19);
                        int y20 = (getMeasuredHeight() - ActionIntroActivity.this.descriptionText2.getMeasuredHeight()) - AndroidUtilities.dp(20.0f);
                        ActionIntroActivity.this.descriptionText2.layout(0, y20, ActionIntroActivity.this.descriptionText2.getMeasuredWidth(), ActionIntroActivity.this.descriptionText2.getMeasuredHeight() + y20);
                        return;
                    }
                    if (i == 3) {
                        if (r > b) {
                            int y21 = ((int) ((height * 0.95f) - ActionIntroActivity.this.imageView.getMeasuredHeight())) / 2;
                            ActionIntroActivity.this.imageView.layout(0, y21, ActionIntroActivity.this.imageView.getMeasuredWidth(), ActionIntroActivity.this.imageView.getMeasuredHeight() + y21);
                            int y22 = y21 + ActionIntroActivity.this.imageView.getMeasuredHeight() + AndroidUtilities.dp(10.0f);
                            ActionIntroActivity.this.subtitleTextView.layout(0, y22, ActionIntroActivity.this.subtitleTextView.getMeasuredWidth(), ActionIntroActivity.this.subtitleTextView.getMeasuredHeight() + y22);
                            int x10 = (int) (width * 0.4f);
                            int y23 = (int) (height * 0.12f);
                            ActionIntroActivity.this.titleTextView.layout(x10, y23, ActionIntroActivity.this.titleTextView.getMeasuredWidth() + x10, ActionIntroActivity.this.titleTextView.getMeasuredHeight() + y23);
                            int x11 = (int) (width * 0.4f);
                            int y24 = (int) (height * 0.24f);
                            ActionIntroActivity.this.descriptionText.layout(x11, y24, ActionIntroActivity.this.descriptionText.getMeasuredWidth() + x11, ActionIntroActivity.this.descriptionText.getMeasuredHeight() + y24);
                            int x12 = (int) ((width * 0.4f) + (((width * 0.6f) - ActionIntroActivity.this.buttonTextView.getMeasuredWidth()) / 2.0f));
                            int y25 = (int) (height * 0.8f);
                            ActionIntroActivity.this.buttonTextView.layout(x12, y25, ActionIntroActivity.this.buttonTextView.getMeasuredWidth() + x12, ActionIntroActivity.this.buttonTextView.getMeasuredHeight() + y25);
                            return;
                        }
                        int y26 = (int) (height * 0.2229f);
                        ActionIntroActivity.this.imageView.layout(0, y26, ActionIntroActivity.this.imageView.getMeasuredWidth(), ActionIntroActivity.this.imageView.getMeasuredHeight() + y26);
                        int y27 = (int) (height * 0.352f);
                        ActionIntroActivity.this.titleTextView.layout(0, y27, ActionIntroActivity.this.titleTextView.getMeasuredWidth(), ActionIntroActivity.this.titleTextView.getMeasuredHeight() + y27);
                        int y28 = (int) (height * 0.409f);
                        ActionIntroActivity.this.subtitleTextView.layout(0, y28, ActionIntroActivity.this.subtitleTextView.getMeasuredWidth(), ActionIntroActivity.this.subtitleTextView.getMeasuredHeight() + y28);
                        int y29 = (int) (height * 0.468f);
                        ActionIntroActivity.this.descriptionText.layout(0, y29, ActionIntroActivity.this.descriptionText.getMeasuredWidth(), ActionIntroActivity.this.descriptionText.getMeasuredHeight() + y29);
                        int x13 = (width - ActionIntroActivity.this.buttonTextView.getMeasuredWidth()) / 2;
                        int y30 = (int) (height * 0.805f);
                        ActionIntroActivity.this.buttonTextView.layout(x13, y30, ActionIntroActivity.this.buttonTextView.getMeasuredWidth() + x13, ActionIntroActivity.this.buttonTextView.getMeasuredHeight() + y30);
                        return;
                    }
                    if (i != 4) {
                        return;
                    }
                }
                if (r > b) {
                    int y31 = (height - ActionIntroActivity.this.imageView.getMeasuredHeight()) / 2;
                    int x14 = ((int) ((width * 0.5f) - ActionIntroActivity.this.imageView.getMeasuredWidth())) / 2;
                    ActionIntroActivity.this.imageView.layout(x14, y31, ActionIntroActivity.this.imageView.getMeasuredWidth() + x14, ActionIntroActivity.this.imageView.getMeasuredHeight() + y31);
                    int x15 = (int) (width * 0.4f);
                    int y32 = (int) (height * 0.14f);
                    ActionIntroActivity.this.titleTextView.layout(x15, y32, ActionIntroActivity.this.titleTextView.getMeasuredWidth() + x15, ActionIntroActivity.this.titleTextView.getMeasuredHeight() + y32);
                    int x16 = (int) (width * 0.4f);
                    int y33 = (int) (height * 0.31f);
                    ActionIntroActivity.this.descriptionText.layout(x16, y33, ActionIntroActivity.this.descriptionText.getMeasuredWidth() + x16, ActionIntroActivity.this.descriptionText.getMeasuredHeight() + y33);
                    int x17 = (int) ((width * 0.4f) + (((width * 0.6f) - ActionIntroActivity.this.buttonTextView.getMeasuredWidth()) / 2.0f));
                    int y34 = (int) (height * 0.78f);
                    ActionIntroActivity.this.buttonTextView.layout(x17, y34, ActionIntroActivity.this.buttonTextView.getMeasuredWidth() + x17, ActionIntroActivity.this.buttonTextView.getMeasuredHeight() + y34);
                    return;
                }
                int y35 = (int) (height * 0.214f);
                int x18 = (width - ActionIntroActivity.this.imageView.getMeasuredWidth()) / 2;
                ActionIntroActivity.this.imageView.layout(x18, y35, ActionIntroActivity.this.imageView.getMeasuredWidth() + x18, ActionIntroActivity.this.imageView.getMeasuredHeight() + y35);
                int y36 = (int) (height * 0.414f);
                ActionIntroActivity.this.titleTextView.layout(0, y36, ActionIntroActivity.this.titleTextView.getMeasuredWidth(), ActionIntroActivity.this.titleTextView.getMeasuredHeight() + y36);
                int y37 = (int) (height * 0.493f);
                ActionIntroActivity.this.descriptionText.layout(0, y37, ActionIntroActivity.this.descriptionText.getMeasuredWidth(), ActionIntroActivity.this.descriptionText.getMeasuredHeight() + y37);
                int x19 = (width - ActionIntroActivity.this.buttonTextView.getMeasuredWidth()) / 2;
                int y38 = (int) (height * 0.71f);
                ActionIntroActivity.this.buttonTextView.layout(x19, y38, ActionIntroActivity.this.buttonTextView.getMeasuredWidth() + x19, ActionIntroActivity.this.buttonTextView.getMeasuredHeight() + y38);
            }
        };
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        ViewGroup viewGroup = (ViewGroup) this.fragmentView;
        viewGroup.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.hui.discovery.-$$Lambda$ActionIntroActivity$6b0pRzNl8CzksRIwylOhNrk5FMk
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return ActionIntroActivity.lambda$createView$0(view, motionEvent);
            }
        });
        viewGroup.addView(this.actionBar);
        ImageView imageView = new ImageView(context);
        this.imageView = imageView;
        viewGroup.addView(imageView);
        TextView textView = new TextView(context);
        this.titleTextView = textView;
        textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.titleTextView.setGravity(1);
        this.titleTextView.setPadding(AndroidUtilities.dp(32.0f), 0, AndroidUtilities.dp(32.0f), 0);
        this.titleTextView.setTextSize(1, 24.0f);
        viewGroup.addView(this.titleTextView);
        TextView textView2 = new TextView(context);
        this.subtitleTextView = textView2;
        textView2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.subtitleTextView.setGravity(1);
        this.subtitleTextView.setTextSize(1, 15.0f);
        this.subtitleTextView.setSingleLine(true);
        this.subtitleTextView.setEllipsize(TextUtils.TruncateAt.END);
        if (this.currentType == 2) {
            this.subtitleTextView.setPadding(AndroidUtilities.dp(24.0f), 0, AndroidUtilities.dp(24.0f), 0);
        } else {
            this.subtitleTextView.setPadding(AndroidUtilities.dp(32.0f), 0, AndroidUtilities.dp(32.0f), 0);
        }
        this.subtitleTextView.setVisibility(8);
        viewGroup.addView(this.subtitleTextView);
        TextView textView3 = new TextView(context);
        this.descriptionText = textView3;
        textView3.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
        this.descriptionText.setGravity(1);
        this.descriptionText.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
        this.descriptionText.setTextSize(1, 15.0f);
        if (this.currentType == 2) {
            this.descriptionText.setPadding(AndroidUtilities.dp(24.0f), 0, AndroidUtilities.dp(24.0f), 0);
        } else {
            this.descriptionText.setPadding(AndroidUtilities.dp(32.0f), 0, AndroidUtilities.dp(32.0f), 0);
        }
        viewGroup.addView(this.descriptionText);
        TextView textView4 = new TextView(context);
        this.descriptionText2 = textView4;
        textView4.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
        this.descriptionText2.setGravity(1);
        this.descriptionText2.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
        this.descriptionText2.setTextSize(1, 13.0f);
        this.descriptionText2.setVisibility(8);
        if (this.currentType == 2) {
            this.descriptionText2.setPadding(AndroidUtilities.dp(18.0f), 0, AndroidUtilities.dp(18.0f), 0);
        } else {
            this.descriptionText2.setPadding(AndroidUtilities.dp(32.0f), 0, AndroidUtilities.dp(32.0f), 0);
        }
        viewGroup.addView(this.descriptionText2);
        TextView textView5 = new TextView(context);
        this.buttonTextView = textView5;
        textView5.setPadding(AndroidUtilities.dp(34.0f), 0, AndroidUtilities.dp(34.0f), 0);
        this.buttonTextView.setGravity(17);
        this.buttonTextView.setTextColor(Theme.getColor(Theme.key_featuredStickers_buttonText));
        this.buttonTextView.setTextSize(1, 14.0f);
        this.buttonTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.buttonTextView.setBackgroundDrawable(Theme.createSimpleSelectorRoundRectDrawable(AndroidUtilities.dp(4.0f), Theme.getColor(Theme.key_featuredStickers_addButton), Theme.getColor(Theme.key_featuredStickers_addButtonPressed)));
        viewGroup.addView(this.buttonTextView);
        this.buttonTextView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.discovery.-$$Lambda$ActionIntroActivity$MX4s_GSLlYtTpVG6KENmvXmtZGI
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createView$2$ActionIntroActivity(view);
            }
        });
        int i = this.currentType;
        if (i == 0) {
            this.imageView.setImageResource(R.drawable.channelintro);
            this.imageView.setScaleType(ImageView.ScaleType.FIT_CENTER);
            this.titleTextView.setText(LocaleController.getString("ChannelAlertTitle", R.string.ChannelAlertTitle));
            this.descriptionText.setText(LocaleController.getString("ChannelAlertText", R.string.ChannelAlertText));
            this.buttonTextView.setText(LocaleController.getString("ChannelAlertCreate2", R.string.ChannelAlertCreate2));
        } else if (i == 1) {
            this.imageView.setBackgroundDrawable(Theme.createCircleDrawable(AndroidUtilities.dp(100.0f), Theme.getColor(Theme.key_chats_archiveBackground)));
            this.imageView.setImageDrawable(new ShareLocationDrawable(context, 3));
            this.imageView.setScaleType(ImageView.ScaleType.CENTER);
            this.titleTextView.setText(LocaleController.getString("PeopleNearby", R.string.PeopleNearby));
            this.descriptionText.setText(LocaleController.getString("PeopleNearbyAccessInfo", R.string.PeopleNearbyAccessInfo));
            this.buttonTextView.setText(LocaleController.getString("PeopleNearbyAllowAccess", R.string.PeopleNearbyAllowAccess));
        } else if (i == 2) {
            this.subtitleTextView.setVisibility(0);
            this.descriptionText2.setVisibility(0);
            this.imageView.setImageResource(Theme.getCurrentTheme().isDark() ? R.drawable.groupsintro2 : R.drawable.groupsintro);
            this.imageView.setScaleType(ImageView.ScaleType.CENTER);
            TextView textView6 = this.subtitleTextView;
            String str = this.currentGroupCreateDisplayAddress;
            if (str == null) {
                str = "";
            }
            textView6.setText(str);
            this.titleTextView.setText(LocaleController.getString("NearbyCreateGroup", R.string.NearbyCreateGroup));
            this.descriptionText.setText(LocaleController.getString("NearbyCreateGroupInfo", R.string.NearbyCreateGroupInfo));
            this.descriptionText2.setText(LocaleController.getString("NearbyCreateGroupInfo2", R.string.NearbyCreateGroupInfo2));
            this.buttonTextView.setText(LocaleController.getString("NearbyStartGroup", R.string.NearbyStartGroup));
        } else if (i == 3) {
            this.subtitleTextView.setVisibility(0);
            this.drawable1 = context.getResources().getDrawable(R.drawable.sim_old);
            this.drawable2 = context.getResources().getDrawable(R.drawable.sim_new);
            this.drawable1.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_changephoneinfo_image), PorterDuff.Mode.MULTIPLY));
            this.drawable2.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_changephoneinfo_image2), PorterDuff.Mode.MULTIPLY));
            this.imageView.setImageDrawable(new CombinedDrawable(this.drawable1, this.drawable2));
            this.imageView.setScaleType(ImageView.ScaleType.CENTER);
            this.subtitleTextView.setText(PhoneFormat.getInstance().format(Marker.ANY_NON_NULL_MARKER + getUserConfig().getCurrentUser().phone));
            this.titleTextView.setText(LocaleController.getString("PhoneNumberChange2", R.string.PhoneNumberChange2));
            this.descriptionText.setText(AndroidUtilities.replaceTags(LocaleController.getString("PhoneNumberHelp", R.string.PhoneNumberHelp)));
            this.buttonTextView.setText(LocaleController.getString("PhoneNumberChange2", R.string.PhoneNumberChange2));
        } else if (i == 4) {
            this.imageView.setBackgroundDrawable(Theme.createCircleDrawable(AndroidUtilities.dp(100.0f), Theme.getColor(Theme.key_chats_archiveBackground)));
            this.imageView.setImageDrawable(new ShareLocationDrawable(context, 3));
            this.imageView.setScaleType(ImageView.ScaleType.CENTER);
            this.titleTextView.setText(LocaleController.getString("PeopleNearby", R.string.PeopleNearby));
            this.descriptionText.setText(LocaleController.getString("PeopleNearbyGpsInfo", R.string.PeopleNearbyGpsInfo));
            this.buttonTextView.setText(LocaleController.getString("PeopleNearbyGps", R.string.PeopleNearbyGps));
        }
        return this.fragmentView;
    }

    static /* synthetic */ boolean lambda$createView$0(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ void lambda$createView$2$ActionIntroActivity(View v) {
        if (getParentActivity() == null) {
            return;
        }
        int i = this.currentType;
        if (i == 0) {
            Bundle args = new Bundle();
            args.putInt("step", 0);
            presentFragment(new ChannelCreateActivity(args), true);
            return;
        }
        if (i == 1) {
            getParentActivity().requestPermissions(new String[]{PermissionUtils.PERMISSION_ACCESS_COARSE_LOCATION, "android.permission.ACCESS_FINE_LOCATION"}, 2);
            return;
        }
        if (i != 3) {
            if (i == 4) {
                try {
                    getParentActivity().startActivity(new Intent("android.settings.LOCATION_SOURCE_SETTINGS"));
                    return;
                } catch (Exception e) {
                    FileLog.e(e);
                    return;
                }
            }
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("PhoneNumberChangeTitle", R.string.PhoneNumberChangeTitle));
        builder.setMessage(LocaleController.getString("PhoneNumberAlert", R.string.PhoneNumberAlert));
        builder.setPositiveButton(LocaleController.getString("Change", R.string.Change), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.discovery.-$$Lambda$ActionIntroActivity$EA8OF90UNcTFP6ymcOfQ9jIhH5M
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i2) {
                this.f$0.lambda$null$1$ActionIntroActivity(dialogInterface, i2);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$null$1$ActionIntroActivity(DialogInterface dialogInterface, int i) {
        presentFragment(new ChangePhoneNumberActivity(), true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        if (this.currentType == 4) {
            boolean enabled = true;
            if (Build.VERSION.SDK_INT >= 28) {
                LocationManager lm = (LocationManager) ApplicationLoader.applicationContext.getSystemService("location");
                enabled = lm.isLocationEnabled();
            } else if (Build.VERSION.SDK_INT >= 19) {
                try {
                    int mode = Settings.Secure.getInt(ApplicationLoader.applicationContext.getContentResolver(), "location_mode", 0);
                    enabled = mode != 0;
                } catch (Throwable e) {
                    FileLog.e(e);
                }
            }
            if (enabled) {
                presentFragment(new NearPersonAndGroupActivity(), true);
            }
        }
    }

    private void showPermissionAlert(boolean byButton) {
        if (getParentActivity() == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setMessage(LocaleController.getString("PermissionNoLocationPosition", R.string.PermissionNoLocationPosition));
        builder.setNegativeButton(LocaleController.getString("PermissionOpenSettings", R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.discovery.-$$Lambda$ActionIntroActivity$dmYxPfP3KPFXIOR1NVRCftEIF1I
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showPermissionAlert$3$ActionIntroActivity(dialogInterface, i);
            }
        });
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$showPermissionAlert$3$ActionIntroActivity(DialogInterface dialog, int which) {
        if (getParentActivity() == null) {
            return;
        }
        try {
            Intent intent = new Intent("android.settings.APPLICATION_DETAILS_SETTINGS");
            intent.setData(Uri.parse("package:" + ApplicationLoader.applicationContext.getPackageName()));
            getParentActivity().startActivity(intent);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public void setGroupCreateAddress(String address, String displayAddress) {
        this.currentGroupCreateAddress = address;
        this.currentGroupCreateDisplayAddress = displayAddress;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onRequestPermissionsResultFragment(int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == 2 && grantResults != null && grantResults.length != 0) {
            if (grantResults[0] != 0) {
                if (getParentActivity() == null) {
                    return;
                }
                AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder.setMessage(LocaleController.getString("PermissionNoLocationPosition", R.string.PermissionNoLocationPosition));
                builder.setNegativeButton(LocaleController.getString("PermissionOpenSettings", R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.discovery.-$$Lambda$ActionIntroActivity$bW4rSRAot2n6cxONDU5onQ_TVDs
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$onRequestPermissionsResultFragment$4$ActionIntroActivity(dialogInterface, i);
                    }
                });
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                showDialog(builder.create());
                return;
            }
            presentFragment(new NearPersonAndGroupActivity(), true);
        }
    }

    public /* synthetic */ void lambda$onRequestPermissionsResultFragment$4$ActionIntroActivity(DialogInterface dialog, int which) {
        if (getParentActivity() == null) {
            return;
        }
        try {
            Intent intent = new Intent("android.settings.APPLICATION_DETAILS_SETTINGS");
            intent.setData(Uri.parse("package:" + ApplicationLoader.applicationContext.getPackageName()));
            getParentActivity().startActivity(intent);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarWhiteSelector), new ThemeDescription(this.titleTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.subtitleTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.descriptionText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6), new ThemeDescription(this.buttonTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_featuredStickers_buttonText), new ThemeDescription(this.buttonTextView, ThemeDescription.FLAG_USEBACKGROUNDDRAWABLE, null, null, null, null, Theme.key_featuredStickers_addButton), new ThemeDescription(this.buttonTextView, ThemeDescription.FLAG_USEBACKGROUNDDRAWABLE | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_featuredStickers_addButtonPressed), new ThemeDescription(null, ThemeDescription.FLAG_TEXTCOLOR, null, null, new Drawable[]{this.drawable1}, null, Theme.key_changephoneinfo_image), new ThemeDescription(null, ThemeDescription.FLAG_TEXTCOLOR, null, null, new Drawable[]{this.drawable2}, null, Theme.key_changephoneinfo_image2)};
    }
}
