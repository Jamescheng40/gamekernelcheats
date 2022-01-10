#pragma once
//#define to_lower(c_char) ((c_char >= 'A' && c_char <= 'Z') ? (c_char + 32) : c_char)
//
//
//__forceinline bool crt_strcmp(WCHAR* str, UNICODE_STRING in_str, bool two)
//{
//	if (!str || !in_str.Buffer)
//		return false;
//
//	wchar_t tmp1, tmp2;
//
//	WCHAR* c1 = str;
//	WCHAR* c2 = (WCHAR *)in_str.Buffer;
//	do
//	{
//		tmp1 = *c1++; tmp2 = *c2++;
//		tmp1 = to_lower(tmp1); tmp2 = to_lower(tmp2);
//
//		if (!tmp1 && (two ? !tmp2 : 1))
//			return true;
//
//	} while (tmp1 == tmp2);
//
//	return false;
//}