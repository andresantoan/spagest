import jwt from "jsonwebtoken"
import { getToken } from "next-auth/jwt"
import type { NextRequest } from "next/server"
import { NextResponse } from "next/server"
import type { JWT } from "next-auth/jwt"

export async function middleware(request: NextRequest) {
	const path = request.nextUrl.pathname
	let token: JWT | null = await getToken({ req: request, secret: process.env.NEXTAUTH_SECRET })

	// ✅ Support mobile (Bearer token)
	if (!token) {
		const authHeader = request.headers.get("authorization")
		if (authHeader?.startsWith("Bearer ")) {
			const bearerToken = authHeader.split(" ")[1]
			try {
				const verified = jwt.verify(bearerToken, process.env.NEXTAUTH_SECRET as string)
				// Convert jwt.verify result to JWT type
				if (typeof verified === "object" && verified !== null) {
					token = verified as JWT
				}
			} catch {
				token = null
			}
		}
	}

	// 🚫 Protected routes
	if (path.startsWith("/admin") || path.startsWith("/staff")) {
		if (!token) return NextResponse.redirect(new URL("/signin", request.url))

		const role = token.role as string | undefined

		// SUPER ADMIN only
		if (path.startsWith("/admin/super") && role !== "SUPER_ADMIN") {
			return NextResponse.redirect(new URL("/dashboard", request.url))
		}

		// ADMIN & SUPER ADMIN
		if (
			path.startsWith("/admin") &&
			!path.startsWith("/admin/super") &&
			(!role || !["ADMIN", "SUPER_ADMIN"].includes(role))
		) {
			return NextResponse.redirect(new URL("/dashboard", request.url))
		}

		// STAFF only
		if (path.startsWith("/staff") && role !== "STAFF") {
			return NextResponse.redirect(new URL("/dashboard", request.url))
		}
	}

	if (path.startsWith("/dashboard") && !token) {
		return NextResponse.redirect(new URL("/signin", request.url))
	}

	return NextResponse.next()
}

export const config = {
	matcher: ["/dashboard/:path*", "/admin/:path*", "/staff/:path*"],
}
