package im.uwrkaxlmjj.ui.hui.login;

import android.text.Editable;
import android.text.TextWatcher;

/* JADX INFO: loaded from: classes5.dex */
public class PhoneSpaceWatcher implements TextWatcher {
    private int actionPosition;
    private int characterAction = -1;
    private boolean ignoreOnPhoneChange;
    private String phoneNumberFormat;
    private int start;

    public PhoneSpaceWatcher(String phoneNumberFormat) {
        this.phoneNumberFormat = phoneNumberFormat;
    }

    @Override // android.text.TextWatcher
    public void beforeTextChanged(CharSequence s, int start, int count, int after) {
        if (count == 0 && after == 1) {
            this.characterAction = 1;
            return;
        }
        if (count == 1 && after == 0) {
            if (s.charAt(start) == ' ' && start > 0) {
                this.characterAction = 3;
                this.actionPosition = start - 1;
                return;
            } else {
                this.characterAction = 2;
                return;
            }
        }
        this.characterAction = -1;
    }

    @Override // android.text.TextWatcher
    public void onTextChanged(CharSequence s, int start, int before, int count) {
        this.start = start;
    }

    @Override // android.text.TextWatcher
    public void afterTextChanged(Editable s) {
        int i;
        int i2;
        if (this.ignoreOnPhoneChange) {
            return;
        }
        int start = this.start;
        String str = s.toString();
        if (this.characterAction == 3) {
            str = str.substring(0, this.actionPosition) + str.substring(this.actionPosition + 1);
            start--;
        }
        StringBuilder builder = new StringBuilder(str.length());
        for (int a = 0; a < str.length(); a++) {
            String ch = str.substring(a, a + 1);
            if ("0123456789".contains(ch)) {
                builder.append(ch);
            }
        }
        this.ignoreOnPhoneChange = true;
        if (this.phoneNumberFormat != null) {
            int a2 = 0;
            while (true) {
                if (a2 >= builder.length()) {
                    break;
                }
                if (a2 < this.phoneNumberFormat.length()) {
                    if (this.phoneNumberFormat.charAt(a2) == ' ') {
                        builder.insert(a2, ' ');
                        a2++;
                        if (start == a2 && (i2 = this.characterAction) != 2 && i2 != 3) {
                            start++;
                        }
                    }
                    a2++;
                } else {
                    builder.insert(a2, ' ');
                    if (start == a2 + 1 && (i = this.characterAction) != 2 && i != 3) {
                        int i3 = start + 1;
                    }
                }
            }
        }
        s.replace(0, s.length(), builder);
        this.ignoreOnPhoneChange = false;
    }

    public void setPhoneNumberFormat(String phoneNumberFormat) {
        this.phoneNumberFormat = phoneNumberFormat;
    }
}
