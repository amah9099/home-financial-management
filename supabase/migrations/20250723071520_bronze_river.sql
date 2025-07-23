/*
  # Fix user creation and profile setup

  1. Database Functions
    - Create function to handle new user profile creation
    - Create function to update shared access when user signs up
  
  2. Triggers
    - Update trigger to use correct function
    - Ensure proper user profile creation
  
  3. Security
    - Fix RLS policies for user creation
    - Ensure anon users can create profiles during signup
*/

-- Create function to handle new user creation
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, email, full_name, avatar_url)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name'),
    NEW.raw_user_meta_data->>'avatar_url'
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to update shared access when user signs up
CREATE OR REPLACE FUNCTION update_shared_access_on_signup()
RETURNS TRIGGER AS $$
BEGIN
  -- Update shared_access records where shared_with_email matches the new user's email
  UPDATE shared_access 
  SET shared_with_id = NEW.id 
  WHERE shared_with_email = NEW.email AND shared_with_id IS NULL;
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Drop existing trigger if it exists
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP TRIGGER IF EXISTS on_profile_created ON public.profiles;

-- Create trigger on auth.users for new user creation
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION handle_new_user();

-- Create trigger on profiles for shared access updates
CREATE TRIGGER on_profile_created
  AFTER INSERT ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION update_shared_access_on_signup();

-- Update RLS policies to allow profile creation during signup
DROP POLICY IF EXISTS "Users can insert own profile" ON profiles;
CREATE POLICY "Users can insert own profile" ON profiles
  FOR INSERT WITH CHECK (
    auth.uid() = id OR 
    -- Allow service role to insert profiles during signup
    auth.jwt() ->> 'role' = 'service_role'
  );

-- Ensure anon users can read shared access for email matching
DROP POLICY IF EXISTS "Users can view shares directed to them" ON shared_access;
CREATE POLICY "Users can view shares directed to them" ON shared_access
  FOR SELECT USING (
    shared_with_id = auth.uid() OR 
    owner_id = auth.uid() OR
    -- Allow checking by email during signup process
    (shared_with_email = auth.jwt() ->> 'email' AND shared_with_id IS NULL)
  );