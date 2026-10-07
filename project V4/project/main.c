#include "raylib.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

#define MAX_PASSWORD_LENGTH 128
#define SUGGESTED_LENGTH 20

#define DESIGN_WIDTH 1500.0f
#define DESIGN_HEIGHT 1000.0f
#define MIN_WINDOW_WIDTH 1000
#define MIN_WINDOW_HEIGHT 700

/* =========================================================
   COLORS
   ========================================================= */

static const Color UI_BG_COLOR     = { 6, 15, 27, 255 };
static const Color UI_PANEL_COLOR  = { 15, 28, 45, 255 };
static const Color UI_INPUT_COLOR  = { 18, 32, 52, 255 };
static const Color UI_ROW_COLOR    = { 18, 32, 50, 255 };
static const Color UI_BORDER_COLOR = { 35, 52, 72, 255 };

static const Color UI_BLUE         = { 43, 125, 235, 255 };
static const Color UI_BLUE_DARK    = { 30, 105, 210, 255 };

static const Color UI_GREEN        = { 40, 190, 100, 255 };
static const Color UI_GREEN_BRIGHT = { 30, 210, 110, 255 };

static const Color UI_ORANGE       = { 245, 160, 35, 255 };
static const Color UI_YELLOW       = { 245, 190, 50, 255 };
static const Color UI_RED          = { 235, 75, 75, 255 };

static const Color UI_TEXT_GRAY    = { 170, 180, 195, 255 };
static const Color UI_RING_GRAY    = { 48, 62, 80, 255 };

/* =========================================================
   RESULT
   ========================================================= */

typedef struct
{
    int length;

    bool hasUpper;
    bool hasLower;
    bool hasNumber;
    bool hasSpecial;

    bool commonPassword;
    bool breachPassword;
    bool repetitiveCharacters;
    bool hasSequentialPattern;

    int score;
    const char *strength;
} PasswordResult;

static bool g_rockyouAvailable = false;

/* =========================================================
   TEXT HELPERS
   ========================================================= */

static void DrawUIText(
    Font font,
    const char *text,
    float x,
    float y,
    float fontSize,
    Color color
)
{
    DrawTextEx(
        font,
        text,
        (Vector2){ x, y },
        fontSize,
        0.0f,
        color
    );
}

static float MeasureUIText(
    Font font,
    const char *text,
    float fontSize
)
{
    return MeasureTextEx(
        font,
        text,
        fontSize,
        0.0f
    ).x;
}

/* =========================================================
   COMMON PASSWORD CHECK
   ========================================================= */

static bool IsCommonPassword(const char *password)
{
    const char *commonPasswords[] =
    {
        "123456", "1234567", "12345678", "123456789",
        "1234567890", "password", "password1", "password123",
        "qwerty", "qwerty123", "admin", "admin123",
        "letmein", "welcome", "abc123", "111111",
        "11111111", "123123", "000000", "iloveyou",
        "football", "dragon", "monkey", "master",
        "login", "pass", "user"
    };

    int count = (int)(sizeof(commonPasswords) /
                      sizeof(commonPasswords[0]));

    char lowerPassword[MAX_PASSWORD_LENGTH + 1];
    int i = 0;

    while (
        i < MAX_PASSWORD_LENGTH &&
        password[i] != '\0'
    )
    {
        lowerPassword[i] =
            (char)tolower((unsigned char)password[i]);
        i++;
    }

    lowerPassword[i] = '\0';

    for (i = 0; i < count; i++)
    {
        if (strcmp(lowerPassword, commonPasswords[i]) == 0)
            return true;
    }

    return false;
}

/* =========================================================
   BREACHED PASSWORD LIST CHECK
   rockyou.txt is used as the breached-password list and must be beside the EXE.
   The comparison is case-insensitive.
   ========================================================= */

static bool EqualsIgnoreCase(
    const char *a,
    const char *b
)
{
    while (*a != '\0' && *b != '\0')
    {
        if (
            tolower((unsigned char)*a) !=
            tolower((unsigned char)*b)
        )
        {
            return false;
        }

        a++;
        b++;
    }

    return *a == '\0' && *b == '\0';
}

static bool IsInRockYou(const char *password)
{
    FILE *file = fopen("rockyou.txt", "rb");

    if (file == NULL)
    {
        g_rockyouAvailable = false;
        return false;
    }

    g_rockyouAvailable = true;

    char line[4096];

    while (fgets(line, sizeof(line), file) != NULL)
    {
        size_t length = strlen(line);

        while (
            length > 0 &&
            (line[length - 1] == '\n' ||
             line[length - 1] == '\r')
        )
        {
            line[--length] = '\0';
        }

        if (EqualsIgnoreCase(password, line))
        {
            fclose(file);
            return true;
        }
    }

    fclose(file);
    return false;
}

/* =========================================================
   REPETITIVE CHARACTER CHECK
   Any character appearing 3+ times anywhere.
   Spaces are included here intentionally because this is
   a separate repetition check, not a character-class check.
   ========================================================= */

static bool HasRepetitiveCharacters(const char *password)
{
    int length = (int)strlen(password);

    if (length < 3)
        return false;

    int counts[256] = {0};

    for (int i = 0; i < length; i++)
    {
        unsigned char c = (unsigned char)password[i];

        counts[c]++;

        if (counts[c] >= 3)
            return true;
    }

    return false;
}

/* =========================================================
   SEQUENTIAL PATTERN CHECK
   Detects 1234, 4321, abcd, dcba, etc.
   ========================================================= */

static bool HasSequentialPattern(const char *password)
{
    int length = (int)strlen(password);

    if (length < 4)
        return false;

    for (int i = 0; i <= length - 4; i++)
    {
        int d1 =
            (unsigned char)password[i + 1] -
            (unsigned char)password[i];

        int d2 =
            (unsigned char)password[i + 2] -
            (unsigned char)password[i + 1];

        int d3 =
            (unsigned char)password[i + 3] -
            (unsigned char)password[i + 2];

        if (
            d1 == d2 &&
            d2 == d3 &&
            (d1 == 1 || d1 == -1)
        )
        {
            return true;
        }
    }

    return false;
}

/* =========================================================
   PASSWORD CHECKER
   IMPORTANT:
   Only explicit punctuation is a special character.
   A SPACE is NOT a special character.
   ========================================================= */

static bool IsSpecialCharacter(unsigned char c)
{
    switch (c)
    {
        case '!':
        case '@':
        case '#':
        case '$':
        case '%':
        case '^':
        case '&':
        case '*':
        case '(':
        case ')':
        case '_':
        case '-':
        case '+':
        case '=':
        case '?':
        case '.':
        case ',':
        case ':':
        case ';':
        case '<':
        case '>':
        case '/':
        case '\\':
        case '|':
        case '~':
        case '`':
        case '"':
        case '\'':
        case '[':
        case ']':
        case '{':
        case '}':
            return true;

        default:
            return false;
    }
}

static PasswordResult CheckPassword(const char *password)
{
    PasswordResult result = {0};

    result.length = (int)strlen(password);

    /* -----------------------------------------------------
       CHARACTER ANALYSIS
       ----------------------------------------------------- */

    for (int i = 0; password[i] != '\0'; i++)
    {
        unsigned char c = (unsigned char)password[i];

        if (isupper(c))
        {
            result.hasUpper = true;
        }
        else if (islower(c))
        {
            result.hasLower = true;
        }
        else if (isdigit(c))
        {
            result.hasNumber = true;
        }
        else if (IsSpecialCharacter(c))
        {
            result.hasSpecial = true;
        }
        /* Spaces and other non-ASCII/non-punctuation characters
           do not automatically become special characters. */
    }

    result.commonPassword =
        IsCommonPassword(password);

    result.breachPassword =
        IsInRockYou(password);

    result.repetitiveCharacters =
        HasRepetitiveCharacters(password);

    result.hasSequentialPattern =
        HasSequentialPattern(password);

    /* -----------------------------------------------------
       SCORE: maximum 100
       ----------------------------------------------------- */

    int score = 0;

    /* LENGTH: 40 */
    if (result.length >= 20)
        score += 40;
    else if (result.length >= 16)
        score += 34;
    else if (result.length >= 14)
        score += 30;
    else if (result.length >= 12)
        score += 25;
    else if (result.length >= 10)
        score += 18;
    else if (result.length >= 8)
        score += 12;
    else if (result.length >= 6)
        score += 6;

    /* CHARACTER VARIETY: 30 */
    int typeCount = 0;

    if (result.hasUpper)   typeCount++;
    if (result.hasLower)   typeCount++;
    if (result.hasNumber)  typeCount++;
    if (result.hasSpecial) typeCount++;

    if (typeCount == 4)
        score += 30;
    else if (typeCount == 3)
        score += 23;
    else if (typeCount == 2)
        score += 15;
    else if (typeCount == 1)
        score += 7;

    /* NOT COMMON: 15 */
    if (!result.commonPassword)
        score += 15;

    /* PATTERN QUALITY: 15 */
    if (
        !result.repetitiveCharacters &&
        !result.hasSequentialPattern
    )
    {
        score += 15;
    }
    else if (
        !result.repetitiveCharacters ||
        !result.hasSequentialPattern
    )
    {
        score += 8;
    }

    /* PENALTIES */
    if (result.commonPassword)
        score -= 45;

    if (result.breachPassword)
        score -= 35;

    if (result.repetitiveCharacters)
        score -= 12;

    if (result.hasSequentialPattern)
        score -= 10;

    /* SHORT PASSWORD PENALTY */
    if (result.length < 8)
        score = score * 60 / 100;
    else if (result.length < 10)
        score = score * 75 / 100;

    if (result.length == 0)
        score = 0;

    /*
       A password found in the breach password list is always
       classified as Very Weak, regardless of its length or
       character variety. It should never receive a strong
       score simply because it contains mixed characters.
    */
    if (result.breachPassword)
        score = 0;

    if (score < 0)
        score = 0;

    if (score > 100)
        score = 100;

    result.score = score;

    if (score <= 19)
        result.strength = "Very Weak";
    else if (score <= 39)
        result.strength = "Weak";
    else if (score <= 59)
        result.strength = "Moderate";
    else if (score <= 79)
        result.strength = "Strong";
    else
        result.strength = "Very Strong";

    return result;
}

/* =========================================================
   RANDOM STRONG PASSWORD
   ========================================================= */

static bool GenerateStrongPassword(
    char *output,
    size_t outputSize
)
{
    const char uppercase[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    const char lowercase[] =
        "abcdefghijklmnopqrstuvwxyz";

    const char numbers[] =
        "0123456789";

    const char special[] =
        "!@#$%^&*";

    const char all[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "!@#$%^&*";

    int allLength = (int)strlen(all);

    if (outputSize < SUGGESTED_LENGTH + 1)
        return false;

    for (int attempt = 0; attempt < 1000; attempt++)
    {
        output[0] =
            uppercase[
                GetRandomValue(
                    0,
                    (int)strlen(uppercase) - 1
                )
            ];

        output[1] =
            lowercase[
                GetRandomValue(
                    0,
                    (int)strlen(lowercase) - 1
                )
            ];

        output[2] =
            numbers[
                GetRandomValue(
                    0,
                    (int)strlen(numbers) - 1
                )
            ];

        output[3] =
            special[
                GetRandomValue(
                    0,
                    (int)strlen(special) - 1
                )
            ];

        for (int i = 4; i < SUGGESTED_LENGTH; i++)
        {
            output[i] =
                all[
                    GetRandomValue(
                        0,
                        allLength - 1
                    )
                ];
        }

        output[SUGGESTED_LENGTH] = '\0';

        for (int i = SUGGESTED_LENGTH - 1; i > 0; i--)
        {
            int j = GetRandomValue(0, i);

            char temp = output[i];
            output[i] = output[j];
            output[j] = temp;
        }

        PasswordResult generated =
            CheckPassword(output);

        if (
            generated.score == 100 &&
            !generated.breachPassword
        )
        {
            return true;
        }
    }

    return false;
}


/* =========================================================
   SUGGESTION HELPERS
   ========================================================= */

static int CountSuggestions(
    const PasswordResult *result,
    bool checked
)
{
    if (!checked)
        return 1;

    int count = 0;

    if (result->length < 12) count++;
    if (!result->hasUpper) count++;
    if (!result->hasLower) count++;
    if (!result->hasNumber) count++;
    if (!result->hasSpecial) count++;
    if (result->commonPassword) count++;
    if (result->breachPassword) count++;
    if (result->repetitiveCharacters) count++;
    if (result->hasSequentialPattern) count++;

    if (
        count == 0 &&
        result->length >= 12 &&
        result->hasUpper &&
        result->hasLower &&
        result->hasNumber &&
        result->hasSpecial
    )
    {
        count = 1;
    }

    return count;
}

static void DrawSuggestionLine(
    Font regularFont,
    const char *text,
    int y,
    Color dotColor
)
{
    DrawCircle(
        85,
        y + 8,
        9,
        dotColor
    );

    DrawUIText(
        regularFont,
        text,
        105,
        y - 4,
        20,
        RAYWHITE
    );
}

/* =========================================================
   DRAW HELPERS
   ========================================================= */

static void DrawPanel(Rectangle rect)
{
    DrawRectangleRounded(
        rect,
        0.08f,
        20,
        UI_PANEL_COLOR
    );

    DrawRectangleRoundedLines(
        rect,
        0.08f,
        20,
        UI_BORDER_COLOR
    );
}

static Color GetStrengthColor(int score)
{
    if (score < 20)
        return UI_RED;

    if (score < 40)
        return UI_ORANGE;

    if (score < 60)
        return UI_YELLOW;

    if (score < 80)
        return UI_GREEN;

    return UI_GREEN_BRIGHT;
}

static void DrawAnalysisRow(
    Font regularFont,
    Font boldFont,
    Rectangle rect,
    const char *label,
    const char *value,
    bool good
)
{
    DrawRectangleRounded(
        rect,
        0.12f,
        12,
        UI_ROW_COLOR
    );

    Color statusColor =
        good ? UI_GREEN : UI_ORANGE;

    DrawCircle(
        (int)rect.x + 25,
        (int)rect.y + 22,
        14,
        statusColor
    );

    if (good)
    {
        DrawLine(
            (int)rect.x + 19,
            (int)rect.y + 21,
            (int)rect.x + 23,
            (int)rect.y + 25,
            WHITE
        );

        DrawLine(
            (int)rect.x + 23,
            (int)rect.y + 25,
            (int)rect.x + 31,
            (int)rect.y + 16,
            WHITE
        );
    }
    else
    {
        DrawUIText(
            boldFont,
            "!",
            rect.x + 21,
            rect.y + 7,
            20,
            WHITE
        );
    }

    DrawUIText(
        regularFont,
        label,
        rect.x + 55,
        rect.y + 7,
        21,
        RAYWHITE
    );

    float valueWidth =
        MeasureUIText(
            regularFont,
            value,
            17
        );

    DrawUIText(
        regularFont,
        value,
        rect.x + rect.width -
            valueWidth - 20,
        rect.y + 7,
        20,
        good ? RAYWHITE : UI_ORANGE
    );
}

/* =========================================================
   MAIN
   ========================================================= */

int main(void)
{
    InitWindow(
        (int)DESIGN_WIDTH,
        (int)DESIGN_HEIGHT,
        "Password Security Checker"
    );

    SetWindowState(FLAG_WINDOW_RESIZABLE);

    SetWindowMinSize(
        MIN_WINDOW_WIDTH,
        MIN_WINDOW_HEIGHT
    );

    SetTargetFPS(60);

    SetRandomSeed((unsigned int)time(NULL));

    /* =====================================================
       FONTS
       ===================================================== */

    Font regularFont =
        LoadFontEx(
            "C:/Windows/Fonts/segoeui.ttf",
            160,
            NULL,
            0
        );

    Font boldFont =
        LoadFontEx(
            "C:/Windows/Fonts/segoeuib.ttf",
            160,
            NULL,
            0
        );

    bool customRegular =
        regularFont.texture.id != 0;

    bool customBold =
        boldFont.texture.id != 0;

    if (!customRegular)
        regularFont = GetFontDefault();

    if (!customBold)
        boldFont = GetFontDefault();

    if (customRegular)
        SetTextureFilter(
            regularFont.texture,
            TEXTURE_FILTER_BILINEAR
        );

    if (customBold)
        SetTextureFilter(
            boldFont.texture,
            TEXTURE_FILTER_BILINEAR
        );

    /* =====================================================
       PASSWORD STATE
       ===================================================== */

    char password[MAX_PASSWORD_LENGTH + 1] = "";
    int passwordLength = 0;

    bool showPassword = false;
    bool checked = false;
    bool showAbout = false;
    bool inputFocused = false;

    /* Scroll offset for the Suggestions panel only. */
    float suggestionScroll = 0.0f;

    PasswordResult result = {0};
    result.score = 0;
    result.strength = "Not Checked";

    /* =====================================================
       SUGGESTED PASSWORD
       ===================================================== */

    char suggestedPassword[SUGGESTED_LENGTH + 1] = "";
    bool hasSuggestion = false;

    char copiedMessage[64] = "";
    double copiedMessageTime = 0;

    if (
        GenerateStrongPassword(
            suggestedPassword,
            sizeof(suggestedPassword)
        )
    )
    {
        hasSuggestion = true;
    }

    /* =====================================================
       DESIGN RECTANGLES
       ===================================================== */

    Rectangle inputBox =
    {
        170, 220, 880, 65
    };

    Rectangle eyeButton =
    {
        925, 220, 125, 65
    };

    Rectangle checkButton =
    {
        1080, 225, 235, 70
    };

    Rectangle aboutButton =
    {
        1335, 55, 110, 40
    };

    Rectangle suggestionBox =
    {
        170, 312, 750, 55
    };

    Rectangle useButton =
    {
        930, 312, 90, 55
    };

    Rectangle copyButton =
    {
        1030, 312, 70, 55
    };

    Rectangle regenerateButton =
    {
        1110, 312, 100, 55
    };

    /* Only this lower panel is scrollable. */
    Rectangle suggestionsPanel =
    {
        45, 865, 1410, 110
    };

    /* =====================================================
       MAIN LOOP
       ===================================================== */

    while (!WindowShouldClose())
    {
        int actualWidth = GetScreenWidth();
        int actualHeight = GetScreenHeight();

        float scaleX =
            (float)actualWidth / DESIGN_WIDTH;

        float scaleY =
            (float)actualHeight / DESIGN_HEIGHT;

        float uiScale =
            scaleX < scaleY ? scaleX : scaleY;

        if (uiScale <= 0.0f)
            uiScale = 1.0f;

        float offsetX =
            (actualWidth -
             DESIGN_WIDTH * uiScale) / 2.0f;

        float offsetY =
            (actualHeight -
             DESIGN_HEIGHT * uiScale) / 2.0f;

        Vector2 screenMouse =
            GetMousePosition();

        Vector2 mouse =
        {
            (screenMouse.x - offsetX) / uiScale,
            (screenMouse.y - offsetY) / uiScale
        };

        /* F11 toggles fullscreen. */
        if (IsKeyPressed(KEY_F11))
            ToggleFullscreen();

        /* =================================================
           MOUSE CURSOR
           ================================================= */

        if (
            CheckCollisionPointRec(
                mouse,
                inputBox
            )
        )
        {
            SetMouseCursor(MOUSE_CURSOR_IBEAM);
        }
        else
        {
            SetMouseCursor(MOUSE_CURSOR_DEFAULT);
        }

        /* =================================================
           INPUT FOCUS
           ================================================= */

        if (
            IsMouseButtonPressed(
                MOUSE_BUTTON_LEFT
            )
        )
        {
            if (
                CheckCollisionPointRec(
                    mouse,
                    inputBox
                )
            )
            {
                inputFocused = true;
            }
            else if (
                !CheckCollisionPointRec(
                    mouse,
                    eyeButton
                ) &&
                !CheckCollisionPointRec(
                    mouse,
                    checkButton
                )
            )
            {
                inputFocused = false;
            }
        }

        /* =================================================
           TEXT INPUT
           ================================================= */

        if (inputFocused)
        {
            int key = GetCharPressed();

            while (key > 0)
            {
                if (
                    key >= 32 &&
                    key <= 126 &&
                    passwordLength <
                        MAX_PASSWORD_LENGTH
                )
                {
                    password[passwordLength] =
                        (char)key;

                    passwordLength++;

                    password[passwordLength] =
                        '\0';

                    checked = false;
                }

                key = GetCharPressed();
            }
        }

        /* =================================================
           BACKSPACE
           ================================================= */

        if (
            inputFocused &&
            IsKeyPressed(KEY_BACKSPACE)
        )
        {
            if (passwordLength > 0)
            {
                passwordLength--;

                password[passwordLength] =
                    '\0';

                checked = false;
            }
        }

        /* =================================================
           ESC = CLEAR
           ================================================= */

        if (IsKeyPressed(KEY_ESCAPE))
        {
            password[0] = '\0';
            passwordLength = 0;
            checked = false;
            inputFocused = false;
            result.score = 0;
            result.strength = "Not Checked";
        }

        /* =================================================
           ABOUT
           ================================================= */

        if (
            CheckCollisionPointRec(
                mouse,
                aboutButton
            ) &&
            IsMouseButtonPressed(
                MOUSE_BUTTON_LEFT
            )
        )
        {
            showAbout = !showAbout;
        }

        /* =================================================
           SHOW / HIDE
           ================================================= */

        if (
            CheckCollisionPointRec(
                mouse,
                eyeButton
            ) &&
            IsMouseButtonPressed(
                MOUSE_BUTTON_LEFT
            )
        )
        {
            showPassword = !showPassword;
            inputFocused = true;
        }

        /* =================================================
           CHECK PASSWORD
           ================================================= */

        if (
            CheckCollisionPointRec(
                mouse,
                checkButton
            ) &&
            IsMouseButtonPressed(
                MOUSE_BUTTON_LEFT
            )
        )
        {
            result = CheckPassword(password);
            checked = true;
            inputFocused = true;
        }

        /* =================================================
           ENTER = CHECK
           ================================================= */

        if (
            inputFocused &&
            IsKeyPressed(KEY_ENTER)
        )
        {
            result = CheckPassword(password);
            checked = true;
        }

        /* =================================================
           NEW SUGGESTION
           ================================================= */

        if (
            CheckCollisionPointRec(
                mouse,
                regenerateButton
            ) &&
            IsMouseButtonPressed(
                MOUSE_BUTTON_LEFT
            )
        )
        {
            if (
                GenerateStrongPassword(
                    suggestedPassword,
                    sizeof(suggestedPassword)
                )
            )
            {
                hasSuggestion = true;
                copiedMessage[0] = '\0';
            }
        }

        /* =================================================
           USE SUGGESTION
           ================================================= */

        if (
            CheckCollisionPointRec(
                mouse,
                useButton
            ) &&
            IsMouseButtonPressed(
                MOUSE_BUTTON_LEFT
            )
        )
        {
            if (hasSuggestion)
            {
                strcpy(
                    password,
                    suggestedPassword
                );

                passwordLength =
                    (int)strlen(password);

                showPassword = true;
                inputFocused = true;

                result =
                    CheckPassword(password);

                checked = true;
            }
        }

        /* =================================================
           COPY SUGGESTION
           ================================================= */

        if (
            CheckCollisionPointRec(
                mouse,
                copyButton
            ) &&
            IsMouseButtonPressed(
                MOUSE_BUTTON_LEFT
            )
        )
        {
            if (hasSuggestion)
            {
                SetClipboardText(
                    suggestedPassword
                );

                strcpy(
                    copiedMessage,
                    "Copied!"
                );

                copiedMessageTime =
                    GetTime();
            }
        }

        /* =================================================
           SUGGESTIONS SCROLL
           Only the suggestion content scrolls.
           ================================================= */

        int suggestionCount =
            CountSuggestions(&result, checked);

        const float suggestionViewportTop = 905.0f;
        const float suggestionViewportBottom = 965.0f;
        const float suggestionRowHeight = 27.0f;

        float suggestionContentHeight =
            (float)suggestionCount * suggestionRowHeight;

        float suggestionViewportHeight =
            suggestionViewportBottom -
            suggestionViewportTop;

        float maxSuggestionScroll =
            suggestionContentHeight -
            suggestionViewportHeight;

        if (maxSuggestionScroll < 0.0f)
            maxSuggestionScroll = 0.0f;

        if (
            CheckCollisionPointRec(
                mouse,
                suggestionsPanel
            ) &&
            maxSuggestionScroll > 0.0f
        )
        {
            suggestionScroll -=
                GetMouseWheelMove() * 32.0f;
        }

        if (!checked)
            suggestionScroll = 0.0f;

        if (suggestionScroll < 0.0f)
            suggestionScroll = 0.0f;

        if (suggestionScroll > maxSuggestionScroll)
            suggestionScroll = maxSuggestionScroll;

        /* =================================================
           DRAW
           ================================================= */

        BeginDrawing();

        ClearBackground(UI_BG_COLOR);

        Camera2D camera = {0};

        camera.target =
            (Vector2){ 0, 0 };

        camera.offset =
            (Vector2){ offsetX, offsetY };

        camera.rotation = 0.0f;
        camera.zoom = uiScale;

        BeginMode2D(camera);

        /* =================================================
           HEADER
           ================================================= */

        DrawCircle(
            48,
            82,
            28,
            UI_BLUE
        );

        DrawUIText(
            boldFont,
            "S",
            37,
            61,
            28,
            WHITE
        );

        DrawUIText(
            boldFont,
            "Password Security Checker",
            80,
            56,
            36,
            RAYWHITE
        );

        bool aboutHover =
            CheckCollisionPointRec(
                mouse,
                aboutButton
            );

        DrawUIText(
            regularFont,
            "i  About",
            aboutButton.x,
            aboutButton.y + 4,
            21,
            aboutHover ? UI_BLUE : RAYWHITE
        );

        /* =================================================
           TOP CARD
           ================================================= */

        Rectangle topCard =
        {
            45, 120, 1410, 255
        };

        DrawPanel(topCard);

        const char *mainTitle =
            "Check the Strength of Your Password";

        float mainTitleWidth =
            MeasureUIText(
                boldFont,
                mainTitle,
                34
            );

        DrawUIText(
            boldFont,
            mainTitle,
            (DESIGN_WIDTH - mainTitleWidth) / 2.0f,
            148,
            34,
            RAYWHITE
        );

        const char *subtitle =
            "Enter your password below to check its strength and get security suggestions.";

        float subtitleWidth =
            MeasureUIText(
                regularFont,
                subtitle,
                20
            );

        DrawUIText(
            regularFont,
            subtitle,
            (DESIGN_WIDTH - subtitleWidth) / 2.0f,
            190,
            20,
            UI_TEXT_GRAY
        );

        /* =================================================
           PASSWORD INPUT
           ================================================= */

        bool inputHover =
            CheckCollisionPointRec(
                mouse,
                inputBox
            );

        DrawRectangleRounded(
            inputBox,
            0.15f,
            20,
            UI_INPUT_COLOR
        );

        DrawRectangleRoundedLines(
            inputBox,
            0.15f,
            20,
            inputFocused
                ? UI_BLUE
                : (inputHover
                    ? UI_BLUE
                    : UI_BORDER_COLOR)
        );

        char displayPassword[
            MAX_PASSWORD_LENGTH + 1
        ];

        if (showPassword)
        {
            strcpy(
                displayPassword,
                password
            );
        }
        else
        {
            for (
                int i = 0;
                i < passwordLength;
                i++
            )
            {
                displayPassword[i] = '*';
            }

            displayPassword[
                passwordLength
            ] = '\0';
        }

        const float inputFontSize = 30.0f;

        DrawUIText(
            regularFont,
            displayPassword,
            inputBox.x + 25,
            inputBox.y + 18,
            inputFontSize,
            RAYWHITE
        );

        /* Blinking text cursor. */
        if (
            inputFocused &&
            ((int)(GetTime() * 2.0) % 2 == 0)
        )
        {
            float textWidth =
                MeasureUIText(
                    regularFont,
                    displayPassword,
                    inputFontSize
                );

            float cursorX =
                inputBox.x +
                25 +
                textWidth +
                2;

            if (
                cursorX <
                eyeButton.x - 10
            )
            {
                DrawRectangle(
                    (int)cursorX,
                    (int)inputBox.y + 15,
                    2,
                    38,
                    UI_BLUE
                );
            }
        }

        /* =================================================
           SHOW / HIDE
           ================================================= */

        bool eyeHover =
            CheckCollisionPointRec(
                mouse,
                eyeButton
            );

        DrawRectangleRounded(
            eyeButton,
            0.18f,
            16,
            eyeHover
                ? (Color){ 26, 47, 70, 255 }
                : UI_INPUT_COLOR
        );

        DrawRectangleRoundedLines(
            eyeButton,
            0.18f,
            16,
            eyeHover
                ? UI_BLUE
                : UI_BORDER_COLOR
        );

        float eyeX =
            eyeButton.x + 25;

        float eyeY =
            eyeButton.y + 35;

        DrawEllipse(
            (int)eyeX,
            (int)eyeY,
            15,
            9,
            UI_TEXT_GRAY
        );

        DrawCircle(
            (int)eyeX,
            (int)eyeY,
            4,
            UI_INPUT_COLOR
        );

        DrawCircle(
            (int)eyeX,
            (int)eyeY,
            2,
            UI_TEXT_GRAY
        );

        DrawUIText(
            boldFont,
            showPassword ? "HIDE" : "SHOW",
            eyeButton.x + 48,
            eyeButton.y + 20,
            16,
            eyeHover ? RAYWHITE : UI_TEXT_GRAY
        );

        /* =================================================
           CHECK BUTTON
           ================================================= */

        bool buttonHover =
            CheckCollisionPointRec(
                mouse,
                checkButton
            );

        DrawRectangleRounded(
            checkButton,
            0.18f,
            20,
            buttonHover
                ? UI_BLUE_DARK
                : UI_BLUE
        );

        const char *buttonText =
            "Check Password";

        float buttonWidth =
            MeasureUIText(
                boldFont,
                buttonText,
                22
            );

        DrawUIText(
            boldFont,
            buttonText,
            checkButton.x +
                (checkButton.width -
                 buttonWidth) / 2.0f,
            checkButton.y + 21,
            20,
            WHITE
        );

        /* =================================================
           SUGGESTED PASSWORD
           ================================================= */

        DrawUIText(
            boldFont,
            "Suggested strong password",
            170,
            288,
            20,
            RAYWHITE
        );

        DrawRectangleRounded(
            suggestionBox,
            0.10f,
            12,
            UI_INPUT_COLOR
        );

        DrawRectangleRoundedLines(
            suggestionBox,
            0.10f,
            12,
            UI_BORDER_COLOR
        );

        if (hasSuggestion)
        {
            DrawUIText(
                regularFont,
                suggestedPassword,
                suggestionBox.x + 20,
                suggestionBox.y + 13,
                20,
                RAYWHITE
            );
        }

        bool useHover =
            CheckCollisionPointRec(
                mouse,
                useButton
            );

        DrawRectangleRounded(
            useButton,
            0.12f,
            12,
            useHover
                ? UI_BLUE_DARK
                : UI_BLUE
        );

        DrawUIText(
            boldFont,
            "Use",
            useButton.x + 28,
            useButton.y + 14,
            19,
            WHITE
        );

        bool copyHover =
            CheckCollisionPointRec(
                mouse,
                copyButton
            );

        DrawRectangleRounded(
            copyButton,
            0.12f,
            12,
            copyHover
                ? UI_BLUE_DARK
                : UI_PANEL_COLOR
        );

        DrawUIText(
            boldFont,
            "Copy",
            copyButton.x + 13,
            copyButton.y + 14,
            18,
            copyHover ? WHITE : UI_TEXT_GRAY
        );

        bool newHover =
            CheckCollisionPointRec(
                mouse,
                regenerateButton
            );

        DrawRectangleRounded(
            regenerateButton,
            0.15f,
            12,
            newHover
                ? UI_BLUE_DARK
                : UI_PANEL_COLOR
        );

        DrawUIText(
            boldFont,
            "New Gen",
            regenerateButton.x + 13,
            regenerateButton.y + 14,
            18,
            newHover ? WHITE : UI_TEXT_GRAY
        );

        if (
            GetTime() -
            copiedMessageTime < 2.0
        )
        {
            DrawUIText(
                regularFont,
                copiedMessage,
                1220,
                330,
                15,
                UI_GREEN
            );
        }

        /* =================================================
           STRENGTH PANEL
           ================================================= */

        Rectangle strengthPanel =
        {
            45, 395, 610, 455
        };

        DrawPanel(strengthPanel);

        DrawUIText(
            boldFont,
            "Password Strength",
            70,
            415,
            30,
            RAYWHITE
        );

        Vector2 center =
        {
            350, 565
        };

        DrawRing(
            center,
            105,
            120,
            135,
            405,
            80,
            UI_RING_GRAY
        );

        float progress =
            checked
                ? (float)result.score / 100.0f
                : 0.0f;

        Color meterColor =
            checked
                ? GetStrengthColor(result.score)
                : UI_TEXT_GRAY;

        if (
            checked &&
            progress > 0.0f
        )
        {
            DrawRing(
                center,
                105,
                120,
                135,
                135 + 270 * progress,
                80,
                meterColor
            );
        }

        char percentText[20];

        snprintf(
            percentText,
            sizeof(percentText),
            "%d%%",
            checked ? result.score : 0
        );

        float percentWidth =
            MeasureUIText(
                boldFont,
                percentText,
                46
            );

        DrawUIText(
            boldFont,
            percentText,
            center.x - percentWidth / 2.0f,
            515,
            50,
            meterColor
        );

        const char *strengthText =
            checked
                ? result.strength
                : "Not Checked";

        const float strengthFontSize =
            36.0f;

        float strengthWidth =
            MeasureUIText(
                boldFont,
                strengthText,
                strengthFontSize
            );

        DrawUIText(
            boldFont,
            strengthText,
            center.x - strengthWidth / 2.0f,
            568,
            strengthFontSize,
            meterColor
        );

        const char *description;

        if (!checked)
        {
            description =
                "Enter a password and click Check Password.";
        }
        else if (result.score >= 80)
        {
            description =
                "Excellent! Your password is very strong.";
        }
        else if (result.score >= 60)
        {
            description =
                "Your password has strong security.";
        }
        else if (result.score >= 40)
        {
            description =
                "Your password has moderate security.";
        }
        else if (result.score >= 20)
        {
            description =
                "Your password needs improvement.";
        }
        else
        {
            description =
                "Your password is very weak.";
        }

        float descriptionWidth =
            MeasureUIText(
                regularFont,
                description,
                17
            );

        DrawUIText(
            regularFont,
            description,
            center.x -
                descriptionWidth / 2.0f,
            610,
            20,
            UI_TEXT_GRAY
        );

        /* Strength scale. */
        DrawRectangle(
            80, 675, 100, 10, UI_RED
        );

        DrawRectangle(
            185, 675, 100, 10, UI_ORANGE
        );

        DrawRectangle(
            290, 675, 100, 10, UI_YELLOW
        );

        DrawRectangle(
            395, 675, 100, 10, UI_GREEN
        );

        DrawRectangle(
            500, 675, 95, 10, UI_GREEN_BRIGHT
        );

        DrawUIText(
            regularFont,
            "Very Weak",
            80,
            696,
            18,
            UI_RED
        );

        DrawUIText(
            regularFont,
            "Weak",
            215,
            696,
            18,
            UI_ORANGE
        );

        DrawUIText(
            regularFont,
            "Moderate",
            315,
            696,
            18,
            UI_YELLOW
        );

        DrawUIText(
            regularFont,
            "Strong",
            420,
            696,
            18,
            UI_GREEN
        );

        DrawUIText(
            regularFont,
            "Very Strong",
            500,
            696,
            18,
            UI_GREEN_BRIGHT
        );

        /* =================================================
           ANALYSIS PANEL
           ================================================= */

        Rectangle analysisPanel =
        {
            675, 395, 780, 455
        };

        DrawPanel(analysisPanel);

        DrawUIText(
            boldFont,
            "Password Analysis",
            700,
            420,
            28,
            RAYWHITE
        );

        char lengthText[20];

        snprintf(
            lengthText,
            sizeof(lengthText),
            "%d",
            checked ? result.length : 0
        );

        DrawAnalysisRow(
            regularFont,
            boldFont,
            (Rectangle){ 695, 455, 740, 45 },
            "Length (12+ characters)",
            lengthText,
            checked && result.length >= 12
        );

        DrawAnalysisRow(
            regularFont,
            boldFont,
            (Rectangle){ 695, 502, 740, 45 },
            "Uppercase Letters (A-Z)",
            checked && result.hasUpper
                ? "Yes" : "No",
            checked && result.hasUpper
        );

        DrawAnalysisRow(
            regularFont,
            boldFont,
            (Rectangle){ 695, 549, 740, 45 },
            "Lowercase Letters (a-z)",
            checked && result.hasLower
                ? "Yes" : "No",
            checked && result.hasLower
        );

        DrawAnalysisRow(
            regularFont,
            boldFont,
            (Rectangle){ 695, 596, 740, 45 },
            "Numbers (0-9)",
            checked && result.hasNumber
                ? "Yes" : "No",
            checked && result.hasNumber
        );

        DrawAnalysisRow(
            regularFont,
            boldFont,
            (Rectangle){ 695, 643, 740, 45 },
            "Special Characters (!@#$%^&*)",
            checked && result.hasSpecial
                ? "Yes" : "No",
            checked && result.hasSpecial
        );

        DrawAnalysisRow(
            regularFont,
            boldFont,
            (Rectangle){ 695, 690, 740, 45 },
            "Common Password",
            checked && result.commonPassword
                ? "Yes" : "No",
            checked && !result.commonPassword
        );

        DrawAnalysisRow(
            regularFont,
            boldFont,
            (Rectangle){ 695, 737, 740, 45 },
            "Repetitive Characters",
            checked && result.repetitiveCharacters
                ? "Yes" : "No",
            checked && !result.repetitiveCharacters
        );

        DrawAnalysisRow(
            regularFont,
            boldFont,
            (Rectangle){ 695, 784, 740, 45 },
            "Appears in Breached Password List",
            !checked
                ? "No"
                : !g_rockyouAvailable
                    ? "Not Available"
                    : result.breachPassword
                        ? "Yes"
                        : "No",
            checked &&
                g_rockyouAvailable &&
                !result.breachPassword
        );

        /* =================================================
           SUGGESTIONS
           Only this lower content area scrolls.
           The heading stays fixed.
           ================================================= */

        DrawPanel(suggestionsPanel);

        DrawUIText(
            boldFont,
            "Suggestions",
            75,
            878,
            27,
            RAYWHITE
        );

        /* Clip only the suggestion list, not the whole panel. */
        int scissorX =
            (int)(offsetX + 68.0f * uiScale);

        int scissorY =
            (int)(offsetY + suggestionViewportTop * uiScale);

        int scissorWidth =
            (int)(1360.0f * uiScale);

        int scissorHeight =
            (int)((suggestionViewportBottom -
                   suggestionViewportTop) * uiScale);

        BeginScissorMode(
            scissorX,
            scissorY,
            scissorWidth,
            scissorHeight
        );

        int suggestionY =
            (int)(suggestionViewportTop -
                  suggestionScroll);

        if (!checked)
        {
            DrawSuggestionLine(
                regularFont,
                "Check your password to receive security suggestions.",
                suggestionY,
                UI_BLUE
            );
        }
        else
        {
            if (result.length < 12)
            {
                DrawSuggestionLine(
                    regularFont,
                    "Use at least 12 characters for a stronger password.",
                    suggestionY,
                    UI_ORANGE
                );

                suggestionY += 27;
            }

            if (!result.hasUpper)
            {
                DrawSuggestionLine(
                    regularFont,
                    "Add at least one uppercase letter (A-Z).",
                    suggestionY,
                    UI_ORANGE
                );

                suggestionY += 27;
            }

            if (!result.hasLower)
            {
                DrawSuggestionLine(
                    regularFont,
                    "Add at least one lowercase letter (a-z).",
                    suggestionY,
                    UI_ORANGE
                );

                suggestionY += 27;
            }

            if (!result.hasNumber)
            {
                DrawSuggestionLine(
                    regularFont,
                    "Add at least one number (0-9).",
                    suggestionY,
                    UI_ORANGE
                );

                suggestionY += 27;
            }

            if (!result.hasSpecial)
            {
                DrawSuggestionLine(
                    regularFont,
                    "Add at least one special character (!@#$%^&*).",
                    suggestionY,
                    UI_ORANGE
                );

                suggestionY += 27;
            }

            if (result.commonPassword)
            {
                DrawSuggestionLine(
                    regularFont,
                    "Avoid common passwords that are easy to guess.",
                    suggestionY,
                    UI_RED
                );

                suggestionY += 27;
            }

            if (result.breachPassword)
            {
                DrawSuggestionLine(
                    regularFont,
                    "This password appears in a breached password list. Do not use it.",
                    suggestionY,
                    UI_RED
                );

                suggestionY += 27;
            }

            if (result.repetitiveCharacters)
            {
                DrawSuggestionLine(
                    regularFont,
                    "Avoid using the same character three or more times.",
                    suggestionY,
                    UI_ORANGE
                );

                suggestionY += 27;
            }

            if (result.hasSequentialPattern)
            {
                DrawSuggestionLine(
                    regularFont,
                    "Avoid predictable sequences such as 1234 or abcd.",
                    suggestionY,
                    UI_ORANGE
                );

                suggestionY += 27;
            }

            if (
                !result.commonPassword &&
                !result.breachPassword &&
                !result.repetitiveCharacters &&
                !result.hasSequentialPattern &&
                result.length >= 12 &&
                result.hasUpper &&
                result.hasLower &&
                result.hasNumber &&
                result.hasSpecial
            )
            {
                DrawSuggestionLine(
                    regularFont,
                    "Excellent! Your password uses multiple security features.",
                    suggestionY,
                    UI_GREEN
                );
            }
        }

        EndScissorMode();

        /* Scrollbar appears only when there is more content. */
        if (maxSuggestionScroll > 0.0f)
        {
            float scrollbarX = 1430.0f;
            float scrollbarTop = suggestionViewportTop;
            float scrollbarHeight =
                suggestionViewportBottom -
                suggestionViewportTop;

            float thumbHeight =
                scrollbarHeight *
                (suggestionViewportHeight /
                 suggestionContentHeight);

            if (thumbHeight < 18.0f)
                thumbHeight = 18.0f;

            float thumbTravel =
                scrollbarHeight - thumbHeight;

            float thumbY =
                scrollbarTop +
                (suggestionScroll /
                 maxSuggestionScroll) *
                thumbTravel;

            DrawRectangleRounded(
                (Rectangle){
                    scrollbarX,
                    scrollbarTop,
                    8,
                    scrollbarHeight
                },
                0.5f,
                8,
                UI_ROW_COLOR
            );

            DrawRectangleRounded(
                (Rectangle){
                    scrollbarX,
                    thumbY,
                    8,
                    thumbHeight
                },
                0.5f,
                8,
                UI_BLUE
            );
        }

        /* =================================================
           FOOTER
           ================================================= */

        const char *footer =
            "Stay safe. Use strong passwords.";

        float footerWidth =
            MeasureUIText(
                regularFont,
                footer,
                17
            );

        DrawUIText(
            regularFont,
            footer,
            (DESIGN_WIDTH - footerWidth) / 2.0f,
            970,
            19,
            UI_TEXT_GRAY
        );

        /* =================================================
           ABOUT POPUP
           ================================================= */

        if (showAbout)
        {
            DrawRectangle(
                0,
                0,
                (int)DESIGN_WIDTH,
                (int)DESIGN_HEIGHT,
                (Color){ 0, 0, 0, 110 }
            );

            Rectangle aboutBox =
            {
                1000, 105, 420, 250
            };

            DrawRectangleRounded(
                aboutBox,
                0.10f,
                20,
                (Color){ 12, 25, 42, 255 }
            );

            DrawRectangleRoundedLines(
                aboutBox,
                0.10f,
                20,
                UI_BLUE
            );

            DrawUIText(
                boldFont,
                "About Project",
                aboutBox.x + 30,
                aboutBox.y + 20,
                29,
                RAYWHITE
            );

            DrawUIText(
                regularFont,
                "Password Security Checker",
                aboutBox.x + 30,
                aboutBox.y + 70,
                19,
                UI_TEXT_GRAY
            );

            DrawUIText(
                regularFont,
                "Made by",
                aboutBox.x + 30,
                aboutBox.y + 110,
                18,
                UI_TEXT_GRAY
            );

            DrawUIText(
                boldFont,
                "Sayan Mondal",
                aboutBox.x + 30,
                aboutBox.y + 137,
                21,
                RAYWHITE
            );

            DrawUIText(
                boldFont,
                "Rudraksh Swami",
                aboutBox.x + 30,
                aboutBox.y + 170,
                21,
                RAYWHITE
            );

            DrawUIText(
                regularFont,
                "Click About again to close",
                aboutBox.x + 30,
                aboutBox.y + 213,
                15,
                UI_TEXT_GRAY
            );
        }

        EndMode2D();

        EndDrawing();
    }

    /* =====================================================
       CLEANUP
       ===================================================== */

    if (customRegular)
        UnloadFont(regularFont);

    if (customBold)
        UnloadFont(boldFont);

    CloseWindow();

    return 0;
}
