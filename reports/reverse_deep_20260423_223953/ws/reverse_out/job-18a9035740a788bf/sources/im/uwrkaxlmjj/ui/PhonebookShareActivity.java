package im.uwrkaxlmjj.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.res.Configuration;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Bundle;
import android.provider.ContactsContract;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.core.net.MailTo;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.exoplayer2.C;
import com.just.agentweb.DefaultWebClient;
import com.snail.antifake.deviceid.ShellAdbUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.PhoneBookSelectActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.DividerCell;
import im.uwrkaxlmjj.ui.cells.EmptyCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.CheckBoxSquare;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity;
import im.uwrkaxlmjj.ui.hui.contacts.AddContactsInfoActivity;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.io.File;
import java.util.ArrayList;
import java.util.Locale;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PhonebookShareActivity extends BaseFragment {
    private ListAdapter adapter;
    private BackupImageView avatarImage;
    private FrameLayout bottomLayout;
    private TLRPC.User currentUser;
    private PhoneBookSelectActivity.PhoneBookSelectActivityDelegate delegate;
    private int detailRow;
    private int emptyRow;
    private int extraHeight;
    private View extraHeightView;
    private boolean isImport;
    private LinearLayoutManager layoutManager;
    private RecyclerListView listView;
    private TextView nameTextView;
    private ArrayList<AndroidUtilities.VcardItem> other;
    private int overscrollRow;
    private ChatActivity parentFragment;
    private int phoneDividerRow;
    private int phoneEndRow;
    private int phoneStartRow;
    private ArrayList<AndroidUtilities.VcardItem> phones;
    private int rowCount;
    private View shadowView;
    private TextView shareTextView;
    private int user_id;
    private int vcardEndRow;
    private int vcardStartRow;

    public class TextCheckBoxCell extends FrameLayout {
        private CheckBoxSquare checkBox;
        private ImageView imageView;
        private TextView textView;
        private TextView valueTextView;

        public TextCheckBoxCell(Context context) {
            float f;
            float f2;
            float f3;
            float f4;
            super(context);
            TextView textView = new TextView(context);
            this.textView = textView;
            textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.textView.setTextSize(1, 16.0f);
            this.textView.setSingleLine(false);
            this.textView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
            this.textView.setEllipsize(TextUtils.TruncateAt.END);
            TextView textView2 = this.textView;
            int i = (LocaleController.isRTL ? 5 : 3) | 48;
            if (LocaleController.isRTL) {
                f = PhonebookShareActivity.this.isImport ? 17 : 64;
            } else {
                f = 71.0f;
            }
            if (LocaleController.isRTL) {
                f2 = 71.0f;
            } else {
                f2 = PhonebookShareActivity.this.isImport ? 17 : 64;
            }
            addView(textView2, LayoutHelper.createFrame(-1.0f, -1.0f, i, f, 10.0f, f2, 0.0f));
            TextView textView3 = new TextView(context);
            this.valueTextView = textView3;
            textView3.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2));
            this.valueTextView.setTextSize(1, 13.0f);
            this.valueTextView.setLines(1);
            this.valueTextView.setMaxLines(1);
            this.valueTextView.setSingleLine(true);
            this.valueTextView.setGravity(LocaleController.isRTL ? 5 : 3);
            TextView textView4 = this.valueTextView;
            int i2 = LocaleController.isRTL ? 5 : 3;
            if (LocaleController.isRTL) {
                f3 = PhonebookShareActivity.this.isImport ? 17 : 64;
            } else {
                f3 = 71.0f;
            }
            if (LocaleController.isRTL) {
                f4 = 71.0f;
            } else {
                f4 = PhonebookShareActivity.this.isImport ? 17 : 64;
            }
            addView(textView4, LayoutHelper.createFrame(-2.0f, -2.0f, i2, f3, 35.0f, f4, 0.0f));
            ImageView imageView = new ImageView(context);
            this.imageView = imageView;
            imageView.setScaleType(ImageView.ScaleType.CENTER);
            this.imageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteGrayIcon), PorterDuff.Mode.MULTIPLY));
            addView(this.imageView, LayoutHelper.createFrame(-2.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 0.0f : 16.0f, 20.0f, LocaleController.isRTL ? 16.0f : 0.0f, 0.0f));
            if (!PhonebookShareActivity.this.isImport) {
                CheckBoxSquare checkBoxSquare = new CheckBoxSquare(context, false);
                this.checkBox = checkBoxSquare;
                checkBoxSquare.setDuplicateParentStateEnabled(false);
                this.checkBox.setFocusable(false);
                this.checkBox.setFocusableInTouchMode(false);
                this.checkBox.setClickable(false);
                addView(this.checkBox, LayoutHelper.createFrame(18.0f, 18.0f, (LocaleController.isRTL ? 3 : 5) | 16, 19.0f, 0.0f, 19.0f, 0.0f));
            }
        }

        @Override // android.view.View
        public void invalidate() {
            super.invalidate();
            CheckBoxSquare checkBoxSquare = this.checkBox;
            if (checkBoxSquare != null) {
                checkBoxSquare.invalidate();
            }
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            measureChildWithMargins(this.textView, widthMeasureSpec, 0, heightMeasureSpec, 0);
            measureChildWithMargins(this.valueTextView, widthMeasureSpec, 0, heightMeasureSpec, 0);
            measureChildWithMargins(this.imageView, widthMeasureSpec, 0, heightMeasureSpec, 0);
            CheckBoxSquare checkBoxSquare = this.checkBox;
            if (checkBoxSquare != null) {
                measureChildWithMargins(checkBoxSquare, widthMeasureSpec, 0, heightMeasureSpec, 0);
            }
            setMeasuredDimension(View.MeasureSpec.getSize(widthMeasureSpec), Math.max(AndroidUtilities.dp(64.0f), this.textView.getMeasuredHeight() + this.valueTextView.getMeasuredHeight() + AndroidUtilities.dp(20.0f)));
        }

        @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
            super.onLayout(changed, left, top, right, bottom);
            int y = this.textView.getMeasuredHeight() + AndroidUtilities.dp(13.0f);
            TextView textView = this.valueTextView;
            textView.layout(textView.getLeft(), y, this.valueTextView.getRight(), this.valueTextView.getMeasuredHeight() + y);
        }

        public void setVCardItem(AndroidUtilities.VcardItem item, int icon) {
            if (!TextUtils.isEmpty(item.fullData)) {
                this.textView.setText(item.getValue(true));
                this.valueTextView.setText(item.getType());
            } else {
                this.textView.setText(LocaleController.getString("NumberUnknown", R.string.NumberUnknown));
                this.valueTextView.setText(LocaleController.getString("PhoneMobile", R.string.PhoneMobile));
            }
            CheckBoxSquare checkBoxSquare = this.checkBox;
            if (checkBoxSquare != null) {
                checkBoxSquare.setChecked(item.checked, false);
            }
            if (icon != 0) {
                this.imageView.setImageResource(icon);
            } else {
                this.imageView.setImageDrawable(null);
            }
        }

        public void setChecked(boolean checked) {
            CheckBoxSquare checkBoxSquare = this.checkBox;
            if (checkBoxSquare != null) {
                checkBoxSquare.setChecked(checked, true);
            }
        }

        public boolean isChecked() {
            CheckBoxSquare checkBoxSquare = this.checkBox;
            return checkBoxSquare != null && checkBoxSquare.isChecked();
        }
    }

    public PhonebookShareActivity(ContactsController.Contact contact, Uri uri, File file, String name) {
        this(0, contact, uri, file, name);
    }

    public PhonebookShareActivity(int user_id, ContactsController.Contact contact, Uri uri, File file, String name) {
        this.other = new ArrayList<>();
        this.phones = new ArrayList<>();
        if (user_id != 0) {
            this.user_id = user_id;
        }
        ArrayList<TLRPC.User> result = null;
        ArrayList<AndroidUtilities.VcardItem> items = new ArrayList<>();
        if (uri != null) {
            result = AndroidUtilities.loadVCardFromStream(uri, this.currentAccount, false, items, name);
        } else if (file != null) {
            result = AndroidUtilities.loadVCardFromStream(Uri.fromFile(file), this.currentAccount, false, items, name);
            file.delete();
            this.isImport = true;
        } else if (contact.key != null) {
            result = AndroidUtilities.loadVCardFromStream(Uri.withAppendedPath(ContactsContract.Contacts.CONTENT_VCARD_URI, contact.key), this.currentAccount, true, items, name);
        } else {
            this.currentUser = contact.user;
            AndroidUtilities.VcardItem item = new AndroidUtilities.VcardItem();
            item.type = 0;
            if (!TextUtils.isEmpty(this.currentUser.phone)) {
                ArrayList<String> arrayList = item.vcardData;
                String str = "TEL;MOBILE:+" + this.currentUser.phone;
                item.fullData = str;
                arrayList.add(str);
            } else {
                ArrayList<String> arrayList2 = item.vcardData;
                item.fullData = "";
                arrayList2.add("");
            }
            this.phones.add(item);
        }
        if (result != null) {
            for (int a = 0; a < items.size(); a++) {
                AndroidUtilities.VcardItem item2 = items.get(a);
                if (item2.type == 0) {
                    boolean exists = false;
                    int b = 0;
                    while (true) {
                        if (b >= this.phones.size()) {
                            break;
                        }
                        if (!this.phones.get(b).getValue(false).equals(item2.getValue(false))) {
                            b++;
                        } else {
                            exists = true;
                            break;
                        }
                    }
                    if (exists) {
                        item2.checked = false;
                    } else {
                        this.phones.add(item2);
                    }
                } else {
                    this.other.add(item2);
                }
            }
            if (result != null && !result.isEmpty()) {
                this.currentUser = result.get(0);
                if (contact != null && contact.user != null) {
                    this.currentUser.photo = contact.user.photo;
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        if (this.currentUser == null) {
            return false;
        }
        this.rowCount = 0;
        int i = 0 + 1;
        this.rowCount = i;
        this.overscrollRow = 0;
        this.rowCount = i + 1;
        this.emptyRow = i;
        if (this.phones.isEmpty()) {
            this.phoneStartRow = -1;
            this.phoneEndRow = -1;
        } else {
            int i2 = this.rowCount;
            this.phoneStartRow = i2;
            int size = i2 + this.phones.size();
            this.rowCount = size;
            this.phoneEndRow = size;
        }
        if (this.other.isEmpty()) {
            this.phoneDividerRow = -1;
            this.vcardStartRow = -1;
            this.vcardEndRow = -1;
        } else {
            if (this.phones.isEmpty()) {
                this.phoneDividerRow = -1;
            } else {
                int i3 = this.rowCount;
                this.rowCount = i3 + 1;
                this.phoneDividerRow = i3;
            }
            int i4 = this.rowCount;
            this.vcardStartRow = i4;
            int size2 = i4 + this.other.size();
            this.rowCount = size2;
            this.vcardEndRow = size2;
        }
        int i5 = this.rowCount;
        this.rowCount = i5 + 1;
        this.detailRow = i5;
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackgroundColor(Theme.getColor(Theme.key_avatar_backgroundActionBarBlue));
        boolean z = false;
        this.actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_avatar_actionBarSelectorBlue), false);
        this.actionBar.setItemsColor(Theme.getColor(Theme.key_avatar_actionBarIconBlue), false);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAddToContainer(false);
        this.extraHeight = 88;
        if (AndroidUtilities.isTablet()) {
            this.actionBar.setOccupyStatusBar(false);
        }
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.PhonebookShareActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    PhonebookShareActivity.this.finishFragment();
                }
            }
        });
        this.fragmentView = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.PhonebookShareActivity.2
            @Override // android.view.ViewGroup
            protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
                if (child == PhonebookShareActivity.this.listView) {
                    boolean result = super.drawChild(canvas, child, drawingTime);
                    if (PhonebookShareActivity.this.parentLayout != null) {
                        int actionBarHeight = 0;
                        int childCount = getChildCount();
                        int a = 0;
                        while (true) {
                            if (a >= childCount) {
                                break;
                            }
                            View view = getChildAt(a);
                            if (view == child || !(view instanceof ActionBar) || view.getVisibility() != 0) {
                                a++;
                            } else if (((ActionBar) view).getCastShadows()) {
                                actionBarHeight = view.getMeasuredHeight();
                            }
                        }
                        PhonebookShareActivity.this.parentLayout.drawHeaderShadow(canvas, actionBarHeight);
                    }
                    return result;
                }
                boolean result2 = super.drawChild(canvas, child, drawingTime);
                return result2;
            }
        };
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setVerticalScrollBarEnabled(false);
        RecyclerListView recyclerListView2 = this.listView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, z) { // from class: im.uwrkaxlmjj.ui.PhonebookShareActivity.3
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        };
        this.layoutManager = linearLayoutManager;
        recyclerListView2.setLayoutManager(linearLayoutManager);
        this.listView.setGlowColor(Theme.getColor(Theme.key_avatar_backgroundActionBarBlue));
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 0.0f, 48.0f));
        this.listView.setAdapter(new ListAdapter(context));
        this.listView.setItemAnimator(null);
        this.listView.setLayoutAnimation(null);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhonebookShareActivity$cO2YUA5x9W4j7CuQjF71zCNeWuE
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$createView$1$PhonebookShareActivity(view, i);
            }
        });
        this.listView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhonebookShareActivity$rN_vpC_hwhNrAim9j023GmAG-qo
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
            public final boolean onItemClick(View view, int i) {
                return this.f$0.lambda$createView$3$PhonebookShareActivity(view, i);
            }
        });
        frameLayout.addView(this.actionBar);
        View view = new View(context);
        this.extraHeightView = view;
        view.setPivotY(0.0f);
        this.extraHeightView.setBackgroundColor(Theme.getColor(Theme.key_avatar_backgroundActionBarBlue));
        frameLayout.addView(this.extraHeightView, LayoutHelper.createFrame(-1, 88.0f));
        View view2 = new View(context);
        this.shadowView = view2;
        view2.setBackgroundResource(R.drawable.header_shadow);
        frameLayout.addView(this.shadowView, LayoutHelper.createFrame(-1, 3.0f));
        BackupImageView backupImageView = new BackupImageView(context);
        this.avatarImage = backupImageView;
        backupImageView.setRoundRadius(AndroidUtilities.dp(21.0f));
        this.avatarImage.setPivotX(0.0f);
        this.avatarImage.setPivotY(0.0f);
        frameLayout.addView(this.avatarImage, LayoutHelper.createFrame(42.0f, 42.0f, 51, 64.0f, 0.0f, 0.0f, 0.0f));
        TextView textView = new TextView(context);
        this.nameTextView = textView;
        textView.setTextColor(Theme.getColor(Theme.key_profile_title));
        this.nameTextView.setTextSize(1, 18.0f);
        this.nameTextView.setLines(1);
        this.nameTextView.setMaxLines(1);
        this.nameTextView.setSingleLine(true);
        this.nameTextView.setEllipsize(TextUtils.TruncateAt.END);
        this.nameTextView.setGravity(3);
        this.nameTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.nameTextView.setPivotX(0.0f);
        this.nameTextView.setPivotY(0.0f);
        frameLayout.addView(this.nameTextView, LayoutHelper.createFrame(-2.0f, -2.0f, 51, 118.0f, 8.0f, 10.0f, 0.0f));
        needLayout();
        this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.PhonebookShareActivity.4
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                if (PhonebookShareActivity.this.layoutManager.getItemCount() == 0) {
                    return;
                }
                int height = 0;
                View child = recyclerView.getChildAt(0);
                if (child != null) {
                    if (PhonebookShareActivity.this.layoutManager.findFirstVisibleItemPosition() == 0) {
                        height = AndroidUtilities.dp(88.0f) + (child.getTop() < 0 ? child.getTop() : 0);
                    }
                    if (PhonebookShareActivity.this.extraHeight != height) {
                        PhonebookShareActivity.this.extraHeight = height;
                        PhonebookShareActivity.this.needLayout();
                    }
                }
            }
        });
        FrameLayout frameLayout2 = new FrameLayout(context);
        this.bottomLayout = frameLayout2;
        frameLayout2.setBackgroundDrawable(Theme.createSelectorWithBackgroundDrawable(Theme.getColor(Theme.key_passport_authorizeBackground), Theme.getColor(Theme.key_passport_authorizeBackgroundSelected)));
        frameLayout.addView(this.bottomLayout, LayoutHelper.createFrame(-1, 48, 80));
        this.bottomLayout.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhonebookShareActivity$HkltUQ7uazUckPEm3RN1Q8Cp7YQ
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                this.f$0.lambda$createView$5$PhonebookShareActivity(view3);
            }
        });
        TextView textView2 = new TextView(context);
        this.shareTextView = textView2;
        textView2.setCompoundDrawablePadding(AndroidUtilities.dp(8.0f));
        this.shareTextView.setTextColor(Theme.getColor(Theme.key_passport_authorizeText));
        if (this.isImport) {
            this.shareTextView.setText(LocaleController.getString("AddContactChat", R.string.AddContactChat));
        } else {
            this.shareTextView.setText(LocaleController.getString("ContactShare", R.string.ContactShare));
        }
        this.shareTextView.setTextSize(1, 14.0f);
        this.shareTextView.setGravity(17);
        this.shareTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.bottomLayout.addView(this.shareTextView, LayoutHelper.createFrame(-2, -1, 17));
        View shadow = new View(context);
        shadow.setBackgroundResource(R.drawable.header_shadow_reverse);
        frameLayout.addView(shadow, LayoutHelper.createFrame(-1.0f, 3.0f, 83, 0.0f, 0.0f, 0.0f, 48.0f));
        AvatarDrawable avatarDrawable = new AvatarDrawable();
        avatarDrawable.setProfile(true);
        avatarDrawable.setInfo(5, this.currentUser.first_name, this.currentUser.last_name);
        avatarDrawable.setColor(Theme.getColor(Theme.key_avatar_backgroundInProfileBlue));
        this.avatarImage.setImage(ImageLocation.getForUser(this.currentUser, false), "50_50", avatarDrawable, this.currentUser);
        this.nameTextView.setText(ContactsController.formatName(this.currentUser.first_name, this.currentUser.last_name));
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$1$PhonebookShareActivity(View view, int position) {
        final AndroidUtilities.VcardItem item;
        int i = this.phoneStartRow;
        if (position >= i && position < this.phoneEndRow) {
            item = this.phones.get(position - i);
        } else {
            int i2 = this.vcardStartRow;
            if (position >= i2 && position < this.vcardEndRow) {
                item = this.other.get(position - i2);
            } else {
                item = null;
            }
        }
        if (item == null) {
            return;
        }
        if (this.isImport) {
            if (item.type == 0) {
                try {
                    Intent intent = new Intent("android.intent.action.DIAL", Uri.parse("tel:" + item.getValue(false)));
                    intent.addFlags(C.ENCODING_PCM_MU_LAW);
                    getParentActivity().startActivityForResult(intent, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
                    return;
                } catch (Exception e) {
                    FileLog.e(e);
                    return;
                }
            }
            if (item.type == 1) {
                Browser.openUrl(getParentActivity(), MailTo.MAILTO_SCHEME + item.getValue(false));
                return;
            }
            if (item.type == 3) {
                String url = item.getValue(false);
                if (!url.startsWith("http")) {
                    url = DefaultWebClient.HTTP_SCHEME + url;
                }
                Browser.openUrl(getParentActivity(), url);
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setItems(new CharSequence[]{LocaleController.getString("Copy", R.string.Copy)}, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhonebookShareActivity$HfAlKQfIARvm2yVXQV9sHctT62E
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i3) {
                    PhonebookShareActivity.lambda$null$0(item, dialogInterface, i3);
                }
            });
            showDialog(builder.create());
            return;
        }
        item.checked = !item.checked;
        if (position >= this.phoneStartRow && position < this.phoneEndRow) {
            boolean hasChecked = false;
            int a = 0;
            while (true) {
                if (a >= this.phones.size()) {
                    break;
                }
                if (!this.phones.get(a).checked) {
                    a++;
                } else {
                    hasChecked = true;
                    break;
                }
            }
            this.bottomLayout.setEnabled(hasChecked);
            this.shareTextView.setAlpha(hasChecked ? 1.0f : 0.5f);
        }
        TextCheckBoxCell cell = (TextCheckBoxCell) view;
        cell.setChecked(item.checked);
    }

    static /* synthetic */ void lambda$null$0(AndroidUtilities.VcardItem item, DialogInterface dialogInterface, int i) {
        if (i == 0) {
            try {
                ClipboardManager clipboard = (ClipboardManager) ApplicationLoader.applicationContext.getSystemService("clipboard");
                ClipData clip = ClipData.newPlainText("label", item.getValue(false));
                clipboard.setPrimaryClip(clip);
                ToastUtils.show(R.string.TextCopied);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    public /* synthetic */ boolean lambda$createView$3$PhonebookShareActivity(View view, int position) {
        final AndroidUtilities.VcardItem item;
        int i = this.phoneStartRow;
        if (position >= i && position < this.phoneEndRow) {
            item = this.phones.get(position - i);
        } else {
            int i2 = this.vcardStartRow;
            if (position >= i2 && position < this.vcardEndRow) {
                item = this.other.get(position - i2);
            } else {
                item = null;
            }
        }
        if (item == null) {
            return false;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setItems(new CharSequence[]{LocaleController.getString("Copy", R.string.Copy)}, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhonebookShareActivity$cqiuwv_038JETYcLDM_Xp1t98z8
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i3) {
                PhonebookShareActivity.lambda$null$2(item, dialogInterface, i3);
            }
        });
        showDialog(builder.create());
        return true;
    }

    static /* synthetic */ void lambda$null$2(AndroidUtilities.VcardItem item, DialogInterface dialogInterface, int i) {
        if (i == 0) {
            try {
                ClipboardManager clipboard = (ClipboardManager) ApplicationLoader.applicationContext.getSystemService("clipboard");
                ClipData clip = ClipData.newPlainText("label", item.getValue(false));
                clipboard.setPrimaryClip(clip);
                if (item.type == 0) {
                    ToastUtils.show(R.string.PhoneCopied);
                } else if (item.type == 1) {
                    ToastUtils.show(R.string.EmailCopied);
                } else if (item.type == 3) {
                    ToastUtils.show(R.string.LinkCopied);
                } else {
                    ToastUtils.show(R.string.TextCopied);
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    public /* synthetic */ void lambda$createView$5$PhonebookShareActivity(View v) {
        StringBuilder builder;
        TLRPC.User user;
        if (this.isImport) {
            if (getParentActivity() == null || this.user_id == 0 || (user = getMessagesController().getUser(Integer.valueOf(this.user_id))) == null) {
                return;
            }
            if (user.self || user.contact) {
                Bundle bundle = new Bundle();
                bundle.putInt("user_id", user.id);
                presentFragment(new NewProfileActivity(bundle));
                return;
            } else {
                Bundle bundle2 = new Bundle();
                bundle2.putInt("from_type", 6);
                presentFragment(new AddContactsInfoActivity(bundle2, user));
                return;
            }
        }
        if (!this.currentUser.restriction_reason.isEmpty()) {
            builder = new StringBuilder(this.currentUser.restriction_reason.get(0).text);
        } else {
            builder = new StringBuilder(String.format(Locale.US, "BEGIN:VCARD\nVERSION:3.0\nFN:%1$s\nEND:VCARD", ContactsController.formatName(this.currentUser.first_name, this.currentUser.last_name)));
        }
        int idx = builder.lastIndexOf("END:VCARD");
        if (idx >= 0) {
            this.currentUser.phone = null;
            for (int a = this.phones.size() - 1; a >= 0; a--) {
                AndroidUtilities.VcardItem item = this.phones.get(a);
                if (item.checked) {
                    if (this.currentUser.phone == null) {
                        this.currentUser.phone = item.getValue(false);
                    }
                    for (int b = 0; b < item.vcardData.size(); b++) {
                        builder.insert(idx, item.vcardData.get(b) + ShellAdbUtils.COMMAND_LINE_END);
                    }
                }
            }
            for (int a2 = this.other.size() - 1; a2 >= 0; a2--) {
                AndroidUtilities.VcardItem item2 = this.other.get(a2);
                if (item2.checked) {
                    for (int b2 = item2.vcardData.size() - 1; b2 >= 0; b2 += -1) {
                        builder.insert(idx, item2.vcardData.get(b2) + ShellAdbUtils.COMMAND_LINE_END);
                    }
                }
            }
            TLRPC.TL_restrictionReason reason = new TLRPC.TL_restrictionReason();
            reason.text = builder.toString();
            reason.reason = "";
            reason.platform = "";
            this.currentUser.restriction_reason.add(reason);
        }
        ChatActivity chatActivity = this.parentFragment;
        if (chatActivity != null && chatActivity.isInScheduleMode()) {
            AlertsCreator.createScheduleDatePickerDialog(getParentActivity(), UserObject.isUserSelf(this.parentFragment.getCurrentUser()), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhonebookShareActivity$Lw1t7cHSJrJhD03NWlLhmW2FMzw
                @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                public final void didSelectDate(boolean z, int i) {
                    this.f$0.lambda$null$4$PhonebookShareActivity(z, i);
                }
            });
        } else {
            this.delegate.didSelectContact(this.currentUser, true, 0);
            finishFragment();
        }
    }

    public /* synthetic */ void lambda$null$4$PhonebookShareActivity(boolean notify, int scheduleDate) {
        this.delegate.didSelectContact(this.currentUser, notify, scheduleDate);
        finishFragment();
    }

    public void setChatActivity(ChatActivity chatActivity) {
        this.parentFragment = chatActivity;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        fixLayout();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        fixLayout();
    }

    public void setDelegate(PhoneBookSelectActivity.PhoneBookSelectActivityDelegate delegate) {
        this.delegate = delegate;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void needLayout() {
        int newTop = (this.actionBar.getOccupyStatusBar() ? AndroidUtilities.statusBarHeight : 0) + ActionBar.getCurrentActionBarHeight();
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) recyclerListView.getLayoutParams();
            if (layoutParams.topMargin != newTop) {
                layoutParams.topMargin = newTop;
                this.listView.setLayoutParams(layoutParams);
                this.extraHeightView.setTranslationY(newTop);
            }
        }
        if (this.avatarImage != null) {
            float diff = this.extraHeight / AndroidUtilities.dp(88.0f);
            this.extraHeightView.setScaleY(diff);
            this.shadowView.setTranslationY(this.extraHeight + newTop);
            this.avatarImage.setScaleX(((diff * 18.0f) + 42.0f) / 42.0f);
            this.avatarImage.setScaleY(((18.0f * diff) + 42.0f) / 42.0f);
            float avatarY = (((this.actionBar.getOccupyStatusBar() ? AndroidUtilities.statusBarHeight : 0) + ((ActionBar.getCurrentActionBarHeight() / 2.0f) * (diff + 1.0f))) - (AndroidUtilities.density * 21.0f)) + (AndroidUtilities.density * 27.0f * diff);
            this.avatarImage.setTranslationX((-AndroidUtilities.dp(47.0f)) * diff);
            this.avatarImage.setTranslationY((float) Math.ceil(avatarY));
            this.nameTextView.setTranslationX(AndroidUtilities.density * (-21.0f) * diff);
            this.nameTextView.setTranslationY((((float) Math.floor(avatarY)) - ((float) Math.ceil(AndroidUtilities.density))) + ((float) Math.floor(AndroidUtilities.density * 7.0f * diff)));
            this.nameTextView.setScaleX((diff * 0.12f) + 1.0f);
            this.nameTextView.setScaleY((0.12f * diff) + 1.0f);
        }
    }

    private void fixLayout() {
        if (this.fragmentView == null) {
            return;
        }
        this.fragmentView.getViewTreeObserver().addOnPreDrawListener(new ViewTreeObserver.OnPreDrawListener() { // from class: im.uwrkaxlmjj.ui.PhonebookShareActivity.5
            @Override // android.view.ViewTreeObserver.OnPreDrawListener
            public boolean onPreDraw() {
                if (PhonebookShareActivity.this.fragmentView != null) {
                    PhonebookShareActivity.this.needLayout();
                    PhonebookShareActivity.this.fragmentView.getViewTreeObserver().removeOnPreDrawListener(this);
                    return true;
                }
                return true;
            }
        });
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return PhonebookShareActivity.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            AndroidUtilities.VcardItem item;
            int icon;
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                if (position == PhonebookShareActivity.this.overscrollRow) {
                    ((EmptyCell) holder.itemView).setHeight(AndroidUtilities.dp(88.0f));
                    return;
                } else {
                    ((EmptyCell) holder.itemView).setHeight(AndroidUtilities.dp(16.0f));
                    return;
                }
            }
            if (itemViewType == 1) {
                TextCheckBoxCell cell = (TextCheckBoxCell) holder.itemView;
                if (position < PhonebookShareActivity.this.phoneStartRow || position >= PhonebookShareActivity.this.phoneEndRow) {
                    item = (AndroidUtilities.VcardItem) PhonebookShareActivity.this.other.get(position - PhonebookShareActivity.this.vcardStartRow);
                    if (position == PhonebookShareActivity.this.vcardStartRow) {
                        icon = R.drawable.profile_info;
                    } else {
                        icon = 0;
                    }
                } else {
                    item = (AndroidUtilities.VcardItem) PhonebookShareActivity.this.phones.get(position - PhonebookShareActivity.this.phoneStartRow);
                    if (position == PhonebookShareActivity.this.phoneStartRow) {
                        icon = R.drawable.profile_phone;
                    } else {
                        icon = 0;
                    }
                }
                cell.setVCardItem(item, icon);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int position = holder.getAdapterPosition();
            return (position >= PhonebookShareActivity.this.phoneStartRow && position < PhonebookShareActivity.this.phoneEndRow) || (position >= PhonebookShareActivity.this.vcardStartRow && position < PhonebookShareActivity.this.vcardEndRow);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 0) {
                view = new EmptyCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 1) {
                view = PhonebookShareActivity.this.new TextCheckBoxCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 2) {
                view = new DividerCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                view.setPadding(AndroidUtilities.dp(72.0f), AndroidUtilities.dp(8.0f), 0, AndroidUtilities.dp(8.0f));
            } else if (viewType == 3) {
                view = new ShadowSectionCell(this.mContext);
                view.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
            }
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != PhonebookShareActivity.this.emptyRow && position != PhonebookShareActivity.this.overscrollRow) {
                if (position < PhonebookShareActivity.this.phoneStartRow || position >= PhonebookShareActivity.this.phoneEndRow) {
                    if (position < PhonebookShareActivity.this.vcardStartRow || position >= PhonebookShareActivity.this.vcardEndRow) {
                        return (position != PhonebookShareActivity.this.phoneDividerRow && position == PhonebookShareActivity.this.detailRow) ? 3 : 2;
                    }
                    return 1;
                }
                return 1;
            }
            return 0;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{TextCheckBoxCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.shareTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_passport_authorizeText), new ThemeDescription(this.bottomLayout, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_passport_authorizeBackground), new ThemeDescription(this.bottomLayout, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_passport_authorizeBackgroundSelected), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextCheckBoxCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextCheckBoxCell.class}, null, null, null, Theme.key_checkboxSquareUnchecked), new ThemeDescription(this.listView, 0, new Class[]{TextCheckBoxCell.class}, null, null, null, Theme.key_checkboxSquareDisabled), new ThemeDescription(this.listView, 0, new Class[]{TextCheckBoxCell.class}, null, null, null, Theme.key_checkboxSquareBackground), new ThemeDescription(this.listView, 0, new Class[]{TextCheckBoxCell.class}, null, null, null, Theme.key_checkboxSquareCheck)};
    }
}
