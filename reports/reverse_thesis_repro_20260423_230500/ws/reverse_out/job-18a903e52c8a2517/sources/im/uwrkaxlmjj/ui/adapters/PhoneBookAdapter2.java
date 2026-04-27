package im.uwrkaxlmjj.ui.adapters;

import android.content.Context;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.phoneformat.PhoneFormat;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.cells.DividerCell;
import im.uwrkaxlmjj.ui.cells.LetterSectionCell;
import im.uwrkaxlmjj.ui.cells.UserCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.util.ArrayList;
import java.util.HashMap;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
public class PhoneBookAdapter2 extends RecyclerListView.SectionsAdapter {
    private int currentAccount = UserConfig.selectedAccount;
    private Context mContext;

    public PhoneBookAdapter2(Context context) {
        this.mContext = context;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public Object getItem(int section, int position) {
        HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (section < sortedUsersSectionsArray.size()) {
            ArrayList<TLRPC.Contact> arr = usersSectionsDict.get(sortedUsersSectionsArray.get(section));
            if (position < arr.size()) {
                return arr.get(position);
            }
            return null;
        }
        return null;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public boolean isEnabled(int section, int row) {
        HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        return row < usersSectionsDict.get(sortedUsersSectionsArray.get(section)).size();
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public int getSectionCount() {
        ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        return sortedUsersSectionsArray.size();
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public int getCountForSection(int section) {
        ArrayList<TLRPC.Contact> arr;
        HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (section < sortedUsersSectionsArray.size() && (arr = usersSectionsDict.get(sortedUsersSectionsArray.get(section))) != null) {
            int count = arr.size();
            if (section != sortedUsersSectionsArray.size() - 1) {
                return count + 1;
            }
            return count;
        }
        return 0;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public View getSectionHeaderView(int section, View view) {
        HashMap<String, ArrayList<TLRPC.Contact>> map = ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (view == null) {
            view = new LetterSectionCell(this.mContext);
        }
        LetterSectionCell cell = (LetterSectionCell) view;
        if (section < sortedUsersSectionsArray.size()) {
            cell.setLetter(sortedUsersSectionsArray.get(section));
        } else {
            cell.setLetter("");
        }
        return view;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View view;
        if (viewType == 0) {
            view = new UserCell(this.mContext, 58, 1, false);
            ((UserCell) view).setNameTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        } else {
            view = new DividerCell(this.mContext);
            view.setPadding(AndroidUtilities.dp(LocaleController.isRTL ? 28.0f : 72.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(LocaleController.isRTL ? 72.0f : 28.0f), AndroidUtilities.dp(8.0f));
        }
        return new RecyclerListView.Holder(view);
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public void onBindViewHolder(int section, int position, RecyclerView.ViewHolder holder) {
        if (holder.getItemViewType() == 0) {
            UserCell userCell = (UserCell) holder.itemView;
            Object object = getItem(section, position);
            TLRPC.User user = null;
            CharSequence charSequence = "";
            if (object instanceof ContactsController.Contact) {
                ContactsController.Contact contact = (ContactsController.Contact) object;
                if (contact.user != null) {
                    user = contact.user;
                } else {
                    userCell.setCurrentId(contact.contact_id);
                    userCell.setData(null, ContactsController.formatName(contact.first_name, contact.last_name), contact.phones.isEmpty() ? "" : PhoneFormat.getInstance().format(contact.phones.get(0)), 0);
                }
            } else if (object instanceof TLRPC.Contact) {
                user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(((TLRPC.Contact) object).user_id));
            } else {
                user = (TLRPC.User) object;
            }
            if (user != null) {
                if (!TextUtils.isEmpty(user.phone)) {
                    charSequence = PhoneFormat.getInstance().format(Marker.ANY_NON_NULL_MARKER + user.phone);
                }
                userCell.setData(user, null, charSequence, 0);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public int getItemViewType(int section, int position) {
        HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        return position < usersSectionsDict.get(sortedUsersSectionsArray.get(section)).size() ? 0 : 1;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
    public String getLetter(int position) {
        ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        int section = getSectionForPosition(position);
        if (section == -1) {
            section = sortedUsersSectionsArray.size() - 1;
        }
        if (section >= 0 && section < sortedUsersSectionsArray.size()) {
            return sortedUsersSectionsArray.get(section);
        }
        return null;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
    public int getPositionForScrollProgress(float progress) {
        return (int) (getItemCount() * progress);
    }
}
