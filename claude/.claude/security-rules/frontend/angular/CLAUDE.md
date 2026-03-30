# Angular Security Rules

Security rules for Angular development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security
- `rules/languages/typescript/CLAUDE.md` - TypeScript security

---

## XSS Prevention

### Rule: Never Bypass Sanitization

**Level**: `strict`

**When**: Rendering dynamic content.

**Do**:
```typescript
import { Component } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
  selector: 'app-content',
  template: `
    <!-- Angular auto-escapes by default -->
    <p>{{ userMessage }}</p>

    <!-- For trusted HTML, sanitize first -->
    <div [innerHTML]="sanitizedHtml"></div>
  `
})
export class ContentComponent {
  userMessage = '<script>alert("xss")</script>';  // Escaped automatically

  constructor(private sanitizer: DomSanitizer) {}

  get sanitizedHtml(): SafeHtml {
    // Only use for content from trusted sources
    return this.sanitizer.bypassSecurityTrustHtml(this.trustedHtml);
  }
}
```

**Don't**:
```typescript
// VULNERABLE: Bypassing for user input
get userContent(): SafeHtml {
  return this.sanitizer.bypassSecurityTrustHtml(this.userProvidedHtml);
}

// VULNERABLE: Trust user-provided URLs
get userUrl(): SafeUrl {
  return this.sanitizer.bypassSecurityTrustUrl(this.userInput);
}
```

**Why**: Bypassing Angular's sanitization with user input enables XSS attacks.

**Refs**: CWE-79, OWASP A03:2025

---

### Rule: Validate Dynamic URLs

**Level**: `strict`

**When**: Binding user input to href, src, or other URL attributes.

**Do**:
```typescript
import { Component } from '@angular/core';

@Component({
  selector: 'app-link',
  template: `
    <a *ngIf="isValidUrl" [href]="sanitizedUrl">Link</a>
  `
})
export class LinkComponent {
  userUrl: string = '';

  get isValidUrl(): boolean {
    try {
      const parsed = new URL(this.userUrl);
      return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  }

  get sanitizedUrl(): string {
    return this.isValidUrl ? this.userUrl : '#';
  }
}
```

**Don't**:
```typescript
// VULNERABLE: javascript: URLs
template: `<a [href]="userUrl">Link</a>`
```

**Why**: `javascript:` URLs execute code when clicked.

**Refs**: CWE-79, CWE-601

---

## Authentication

### Rule: Use HTTP Interceptors for Auth

**Level**: `strict`

**When**: Adding authentication to API requests.

**Do**:
```typescript
import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler } from '@angular/common/http';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  intercept(req: HttpRequest<any>, next: HttpHandler) {
    // Token from httpOnly cookie (handled by browser)
    // Or use a secure token service
    const authReq = req.clone({
      withCredentials: true,  // Send cookies
      setHeaders: {
        'X-CSRF-Token': this.csrfService.getToken()
      }
    });
    return next.handle(authReq);
  }
}

// app.module.ts
providers: [
  { provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true }
]
```

**Don't**:
```typescript
// VULNERABLE: Token in localStorage accessible via XSS
const token = localStorage.getItem('token');
headers.set('Authorization', `Bearer ${token}`);
```

**Why**: Tokens in localStorage are accessible to XSS attacks.

**Refs**: CWE-922, OWASP A02:2025

---

## Input Validation

### Rule: Validate Form Inputs

**Level**: `strict`

**When**: Processing user form submissions.

**Do**:
```typescript
import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';

@Component({
  selector: 'app-login',
  template: `
    <form [formGroup]="loginForm" (ngSubmit)="onSubmit()">
      <input formControlName="email" type="email">
      <div *ngIf="loginForm.get('email')?.errors?.['email']">
        Invalid email
      </div>
      <input formControlName="password" type="password">
      <button type="submit" [disabled]="loginForm.invalid">Login</button>
    </form>
  `
})
export class LoginComponent {
  loginForm: FormGroup;

  constructor(private fb: FormBuilder) {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(8)]]
    });
  }

  onSubmit() {
    if (this.loginForm.valid) {
      this.authService.login(this.loginForm.value);
    }
  }
}
```

**Don't**:
```typescript
// VULNERABLE: No validation
onSubmit() {
  this.authService.login({
    email: this.emailInput,
    password: this.passwordInput
  });
}
```

**Why**: Unvalidated input causes errors and enables injection attacks.

**Refs**: CWE-20, OWASP A03:2025

---

## Route Guards

### Rule: Implement Route Guards

**Level**: `warning`

**When**: Protecting routes.

**Do**:
```typescript
import { Injectable } from '@angular/core';
import { CanActivate, Router, UrlTree } from '@angular/router';

@Injectable({ providedIn: 'root' })
export class AuthGuard implements CanActivate {
  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  canActivate(): boolean | UrlTree {
    if (this.authService.isAuthenticated()) {
      return true;
    }
    return this.router.createUrlTree(['/login']);
  }
}

// routes
const routes: Routes = [
  {
    path: 'dashboard',
    component: DashboardComponent,
    canActivate: [AuthGuard]
  },
  {
    path: 'admin',
    component: AdminComponent,
    canActivate: [AuthGuard, AdminGuard]
  }
];
```

**Don't**:
```typescript
// VULNERABLE: No route protection
const routes: Routes = [
  { path: 'admin', component: AdminComponent }  // Anyone can access
];
```

**Why**: Guards provide UX for auth flows, but server must still validate.

**Refs**: CWE-862

---

## API Security

### Rule: Validate API Responses

**Level**: `warning`

**When**: Processing data from APIs.

**Do**:
```typescript
import { z } from 'zod';

const UserSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  name: z.string()
});

@Injectable({ providedIn: 'root' })
export class UserService {
  constructor(private http: HttpClient) {}

  getUser(id: number): Observable<User> {
    return this.http.get(`/api/users/${id}`).pipe(
      map(response => {
        // Validate response structure
        return UserSchema.parse(response);
      }),
      catchError(error => {
        if (error instanceof z.ZodError) {
          console.error('Invalid API response', error);
        }
        throw error;
      })
    );
  }
}
```

**Don't**:
```typescript
// VULNERABLE: Assumes response structure
getUser(id: number): Observable<User> {
  return this.http.get<User>(`/api/users/${id}`);  // Type assertion only
}
```

**Why**: Malformed responses can crash the app or inject unexpected data.

**Refs**: CWE-20

---

## Content Security

### Rule: Configure Content Security Policy

**Level**: `warning`

**When**: Deploying the application.

**Do**:
```typescript
// In server configuration or meta tag
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self';
               script-src 'self';
               style-src 'self' 'unsafe-inline';
               img-src 'self' https://cdn.myapp.com;">

// angular.json - Enable subresource integrity
{
  "projects": {
    "my-app": {
      "architect": {
        "build": {
          "options": {
            "subresourceIntegrity": true
          }
        }
      }
    }
  }
}
```

**Don't**:
```html
<!-- VULNERABLE: Allows any source -->
<meta http-equiv="Content-Security-Policy"
      content="default-src *; script-src 'unsafe-eval'">
```

**Why**: CSP prevents XSS by controlling allowed content sources.

**Refs**: OWASP A05:2025

---

## State Management

### Rule: Don't Store Sensitive Data in Client State

**Level**: `strict`

**When**: Managing application state with NgRx or services.

**Do**:
```typescript
// state/user.reducer.ts
export interface UserState {
  id: number | null;
  email: string | null;
  name: string | null;
  isAuthenticated: boolean;
  // Don't store tokens here
}

// auth.service.ts
@Injectable({ providedIn: 'root' })
export class AuthService {
  async login(credentials: Credentials): Promise<void> {
    // Token stored in httpOnly cookie by server
    const response = await this.http.post('/api/login', credentials).toPromise();
    this.store.dispatch(loginSuccess({ user: response.user }));
  }
}
```

**Don't**:
```typescript
// VULNERABLE: Tokens accessible via XSS
export interface UserState {
  accessToken: string;
  refreshToken: string;
}
```

**Why**: Client-side state is accessible to XSS attacks.

**Refs**: CWE-922, OWASP A02:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Never bypass sanitization | strict | CWE-79 |
| Validate dynamic URLs | strict | CWE-79 |
| HTTP interceptors for auth | strict | CWE-922 |
| Validate form inputs | strict | CWE-20 |
| Route guards | warning | CWE-862 |
| Validate API responses | warning | CWE-20 |
| Content Security Policy | warning | - |
| No sensitive client state | strict | CWE-922 |

---

## Version History

- **v1.0.0** - Initial Angular security rules
